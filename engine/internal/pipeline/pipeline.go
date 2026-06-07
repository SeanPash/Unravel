// Package pipeline wires every engine subcomponent into the streaming loop.
// Source -> schema mapper -> graph -> scorer -> (chain extractor + narrator)
// -> WebSocket broadcaster. The scorer's threshold signal is consumed in a
// separate goroutine so chain extraction and the AI call never stall ingest.
package pipeline

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"sync"
	"time"

	"github.com/luigifernandez/unravel/engine/internal/ai"
	"github.com/luigifernandez/unravel/engine/internal/api"
	"github.com/luigifernandez/unravel/engine/internal/chain"
	"github.com/luigifernandez/unravel/engine/internal/graph"
	"github.com/luigifernandez/unravel/engine/internal/schema"
	"github.com/luigifernandez/unravel/engine/internal/scorer"
	"github.com/luigifernandez/unravel/engine/internal/splunk"
	"github.com/luigifernandez/unravel/engine/internal/types"
)

// Config holds the wired-up dependencies. All fields are required except
// Logger, which defaults to slog.Default(), and HEC, which is optional.
type Config struct {
	Source      splunk.Source
	Graph       *graph.Graph
	Scorer      *scorer.Scorer
	Narrator    ai.Narrator
	Broadcaster *api.Broadcaster
	Logger      *slog.Logger

	// HEC is the optional Splunk write-back sink. When nil, chain results are
	// only broadcast over WebSocket and never echoed back to Splunk.
	HEC *splunk.HECClient

	// NarrationTimeout caps each LLM call. Defaults to 20s.
	NarrationTimeout time.Duration

	// HECTimeout caps each HEC write. Defaults to 5s.
	HECTimeout time.Duration

	// SignalDebounce coalesces a burst of scorer signals into a single chain
	// extraction. After a signal arrives, the pipeline waits this long for
	// another signal; only when the burst goes quiet does it walk the graph.
	// Default is 250ms in production. Tests can lower it for snappier runs.
	SignalDebounce time.Duration
}

// Pipeline owns the streaming goroutine and a worker that drains scorer signals.
type Pipeline struct {
	cfg Config
	wg  sync.WaitGroup
}

// New validates cfg and returns a runnable Pipeline.
func New(cfg Config) (*Pipeline, error) {
	if cfg.Source == nil || cfg.Graph == nil || cfg.Scorer == nil || cfg.Narrator == nil || cfg.Broadcaster == nil {
		return nil, errors.New("pipeline: missing required dependency")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.NarrationTimeout <= 0 {
		cfg.NarrationTimeout = 20 * time.Second
	}
	if cfg.HECTimeout <= 0 {
		cfg.HECTimeout = 5 * time.Second
	}
	if cfg.SignalDebounce <= 0 {
		cfg.SignalDebounce = 250 * time.Millisecond
	}
	return &Pipeline{cfg: cfg}, nil
}

// Run blocks until ctx is canceled or the source channel closes. Returns nil
// on a clean shutdown.
func (p *Pipeline) Run(ctx context.Context) error {
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		p.consumeSignals(ctx)
	}()

	p.processEvents(ctx)
	p.wg.Wait()
	return nil
}

func (p *Pipeline) processEvents(ctx context.Context) {
	events := p.cfg.Source.Events()
	for {
		select {
		case <-ctx.Done():
			return
		case raw, ok := <-events:
			if !ok {
				return
			}
			p.handleRaw(raw)
		}
	}
}

func (p *Pipeline) handleRaw(raw splunk.RawEvent) {
	parsed, err := parse(raw)
	if err != nil {
		if !errors.Is(err, schema.ErrUnsupportedEvent) {
			p.cfg.Logger.Debug("parse skipped", "kind", raw.Kind, "err", err)
		}
		return
	}
	updates := materialize(p.cfg.Graph, p.cfg.Scorer, parsed)
	for _, u := range updates {
		p.broadcastGraphUpdate(u.node, u.edge)
		score := p.cfg.Scorer.ScoreEdge(u.edge, p.cfg.Graph)
		u.edge.Confidence = score
		p.broadcastScore(u.edge.ID, score)
	}
}

func (p *Pipeline) broadcastGraphUpdate(n *types.Node, e *types.Edge) {
	payload := types.GraphUpdatePayload{
		Nodes: []types.Node{*n},
		Edges: []types.Edge{*e},
	}
	msg, err := types.NewMessage(types.MsgTypeGraphUpdate, payload)
	if err != nil {
		p.cfg.Logger.Warn("encode graph_update", "err", err)
		return
	}
	p.cfg.Broadcaster.Send(msg)
}

func (p *Pipeline) broadcastScore(edgeID string, score float64) {
	msg, err := types.NewMessage(types.MsgTypeScoreUpdate, types.ScoreUpdatePayload{
		EdgeID: edgeID,
		Score:  score,
	})
	if err != nil {
		p.cfg.Logger.Warn("encode score_update", "err", err)
		return
	}
	p.cfg.Broadcaster.Send(msg)
}

// consumeSignals runs the chain extractor and narrator in response to scorer
// trigger signals. A burst of signals (one per scored edge) is coalesced into
// a single chain extraction once the burst goes quiet, so we walk the graph
// at its final state rather than after the first edge.
func (p *Pipeline) consumeSignals(ctx context.Context) {
	sigs := p.cfg.Scorer.Signals()
	var pending *scorer.Signal
	timer := time.NewTimer(time.Hour)
	if !timer.Stop() {
		<-timer.C
	}
	for {
		select {
		case <-ctx.Done():
			return
		case sig, ok := <-sigs:
			if !ok {
				if pending != nil {
					p.handleSignal(ctx, *pending)
				}
				return
			}
			pending = &sig
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(p.cfg.SignalDebounce)
		case <-timer.C:
			if pending != nil {
				sig := *pending
				pending = nil
				p.handleSignal(ctx, sig)
			}
		}
	}
}

func (p *Pipeline) handleSignal(ctx context.Context, sig scorer.Signal) {
	scoreFn := func(edgeID string) float64 {
		if e := p.cfg.Graph.Edge(edgeID); e != nil {
			return e.Confidence
		}
		return 0
	}
	result := chain.Extract(p.cfg.Graph, scoreFn, sig.HotNode)
	if len(result.Steps) == 0 {
		return
	}
	chainMsg, err := types.NewMessage(types.MsgTypeChainResult, result)
	if err == nil {
		p.cfg.Broadcaster.Send(chainMsg)
	}
	p.sendHEC(ctx, result)

	nctx, cancel := context.WithTimeout(ctx, p.cfg.NarrationTimeout)
	defer cancel()
	narr, err := p.cfg.Narrator.Narrate(nctx, result)
	if err != nil {
		p.cfg.Logger.Warn("narrate", "err", err)
		return
	}
	narrMsg, err := types.NewMessage(types.MsgTypeNarration, narr)
	if err == nil {
		p.cfg.Broadcaster.Send(narrMsg)
	}
}

// sendHEC fires the optional Splunk write-back in a goroutine so a slow or
// unreachable HEC endpoint never stalls ingest or narration. Nil-safe.
func (p *Pipeline) sendHEC(ctx context.Context, result types.ChainResultPayload) {
	if p.cfg.HEC == nil {
		return
	}
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		hctx, cancel := context.WithTimeout(ctx, p.cfg.HECTimeout)
		defer cancel()
		if err := p.cfg.HEC.Send(hctx, result); err != nil {
			p.cfg.Logger.Warn("hec send", "err", err)
		}
	}()
}

// edgeUpdate ties a freshly appended edge to the destination node so we can
// broadcast a meaningful graph_update payload (the new edge plus its newest
// endpoint).
type edgeUpdate struct {
	node *types.Node
	edge *types.Edge
}

// parse dispatches to the per-source schema parser.
func parse(raw splunk.RawEvent) (any, error) {
	switch raw.Kind {
	case splunk.SourceSysmon:
		return schema.ParseSysmon(raw.Raw)
	case splunk.SourceWinsec:
		return schema.ParseWinSec(raw.Raw)
	case splunk.SourceADAudit:
		return schema.ParseADAudit(raw.Raw)
	default:
		return nil, fmt.Errorf("unknown source kind %q", raw.Kind)
	}
}

// materialize converts a typed event into one or more graph node+edge pairs.
// Each returned edge has been appended to g; the caller is responsible for
// scoring and broadcasting.
func materialize(g *graph.Graph, s *scorer.Scorer, ev any) []edgeUpdate {
	switch e := ev.(type) {
	case types.ProcessCreate:
		parent := g.FindOrCreateNode(types.NodeKindProcess, processKey(e.Host, e.ParentPID), labelImage(e.ParentImage), map[string]any{
			"pid":  e.ParentPID,
			"host": e.Host,
		})
		child := g.FindOrCreateNode(types.NodeKindProcess, processKey(e.Host, e.PID), labelImage(e.Image), map[string]any{
			"pid":  e.PID,
			"host": e.Host,
			"user": e.User,
		})
		edge := g.AppendEdge(parent, child, types.EdgeKindSpawned, e.TS, 0, e.EventID)
		return []edgeUpdate{{node: child, edge: edge}}

	case types.ProcessAccess:
		src := g.FindOrCreateNode(types.NodeKindProcess, processKey(e.Host, e.SourcePID), labelImage(e.SourceImage), map[string]any{
			"pid":  e.SourcePID,
			"host": e.Host,
		})
		dst := g.FindOrCreateNode(types.NodeKindProcess, processKey(e.Host, e.TargetPID), labelImage(e.TargetImage), map[string]any{
			"pid":  e.TargetPID,
			"host": e.Host,
		})
		kind := types.EdgeKindAccessedCredential
		if isLSASS(e.TargetImage) {
			kind = types.EdgeKindDumpedMemoryOf
		}
		edge := g.AppendEdge(src, dst, kind, e.TS, 0, e.EventID)
		return []edgeUpdate{{node: dst, edge: edge}}

	case types.LogonSuccess:
		user := g.FindOrCreateNode(types.NodeKindUser, userKey(e.TargetDomain, e.TargetUser), labelUser(e.TargetDomain, e.TargetUser), map[string]any{
			"sid":  e.TargetSID,
			"host": e.Host,
		})
		host := g.FindOrCreateNode(types.NodeKindHost, e.Host, e.Host, map[string]any{
			"ip": e.IPAddress,
		})
		edge := g.AppendEdge(user, host, types.EdgeKindAuthenticatedAs, e.TS, 0, e.EventID)
		s.SetAuthKind(edge, "interactive")
		return []edgeUpdate{{node: host, edge: edge}}

	case types.KerberosService:
		user := g.FindOrCreateNode(types.NodeKindUser, userKey(e.TargetDomain, e.TargetUser), labelUser(e.TargetDomain, e.TargetUser), map[string]any{
			"host": e.Host,
		})
		target := g.FindOrCreateNode(types.NodeKindHost, e.ServiceName, e.ServiceName, map[string]any{
			"ip": e.IPAddress,
		})
		edge := g.AppendEdge(user, target, types.EdgeKindAuthenticatedAs, e.TS, 0, e.EventID)
		s.SetAuthKind(edge, "kerberos")
		return []edgeUpdate{{node: target, edge: edge}}

	case types.FileCreate, types.NetworkConnect, types.LogonFailure, types.SpecialLogon, types.KerberosTGT, types.ADEvent:
		// Recognized but not yet mapped to graph edges in Phase 1.
		return nil
	}
	return nil
}

func processKey(host string, pid int) string {
	return host + ":" + strconv.Itoa(pid)
}

func userKey(domain, user string) string {
	if domain == "" {
		return user
	}
	return domain + "\\" + user
}

func labelUser(domain, user string) string {
	if domain == "" {
		return user
	}
	return domain + "\\" + user
}

// labelImage returns the trailing path component (e.g. "powershell.exe") so
// the UI shows readable node labels instead of full Windows paths.
func labelImage(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '\\' || path[i] == '/' {
			return path[i+1:]
		}
	}
	return path
}

func isLSASS(image string) bool {
	return labelImage(image) == "lsass.exe"
}
