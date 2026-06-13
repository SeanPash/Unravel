// Package pipeline wires every engine subcomponent into the streaming loop.
// Source -> schema mapper -> graph -> scorer -> (chain extractor + narrator)
// -> WebSocket broadcaster. The scorer's threshold signal is consumed in a
// separate goroutine so chain extraction and the AI call never stall ingest.
package pipeline

import (
	"context"
	"errors"
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

// HECSink is satisfied by *splunk.HECClient. Defined here so the pipeline
// package does not import the splunk package circularly via its own type.
type HECSink interface {
	Send(ctx context.Context, event any) error
}

// Config holds the wired-up dependencies. All fields are required except
// Logger (defaults to slog.Default()) and HEC (nil disables write-back).
type Config struct {
	Source      splunk.Source
	Graph       *graph.Graph
	Scorer      *scorer.Scorer
	Narrator    ai.Narrator
	Broadcaster *api.Broadcaster
	// HEC is the optional Splunk write-back sink. When nil, chain results
	// are not forwarded to Splunk.
	HEC    HECSink
	Logger *slog.Logger

	// NarrationTimeout caps each LLM call. Defaults to 20s.
	NarrationTimeout time.Duration

	// IntelAgent runs concurrently with the narrator on each extracted chain.
	// When nil, no threat_intel message is produced.
	IntelAgent ai.ThreatIntelAgent

	// IntelTimeout caps the threat-intel agent call. Defaults to 30s.
	IntelTimeout time.Duration

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
	if cfg.IntelTimeout <= 0 {
		cfg.IntelTimeout = 30 * time.Second
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
	updates := materialize(p.cfg.Graph, parsed)
	for _, u := range updates {
		p.broadcastGraphUpdate(u.node, u.edge)
		score := p.cfg.Scorer.ScoreEdge(u.edge, p.cfg.Graph)
		p.cfg.Graph.SetEdgeConfidence(u.edge.ID, score)
		p.broadcastScore(u.edge.ID, score)
	}
	if len(updates) > 0 {
		p.broadcastLogEvent(raw, updates[0].edge.SourceEventID)
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

func (p *Pipeline) broadcastLogEvent(raw splunk.RawEvent, eventID string) {
	msg, err := types.NewMessage(types.MsgTypeLogEvent, types.LogEventPayload{
		EventID: eventID,
		TS:      raw.TS.Unix(),
		Source:  string(raw.Kind),
		Raw:     raw.Raw,
	})
	if err != nil {
		p.cfg.Logger.Warn("encode log_event", "err", err)
		return
	}
	p.cfg.Broadcaster.Send(msg)
}

// consumeSignals runs the chain extractor and narrator in response to scorer
// trigger signals. A burst of signals for the same incident is coalesced into
// a single chain extraction once the burst goes quiet. Signals from different
// incidents are tracked separately so concurrent incidents each produce their
// own chain extraction.
func (p *Pipeline) consumeSignals(ctx context.Context) {
	sigs := p.cfg.Scorer.Signals()
	pending := map[string]scorer.Signal{}
	flush := func() {
		for _, sig := range pending {
			p.handleSignal(ctx, sig)
		}
		pending = map[string]scorer.Signal{}
	}
	timer := time.NewTimer(time.Hour)
	if !timer.Stop() {
		<-timer.C
	}
	for {
		select {
		case <-ctx.Done():
			// Shutdown takes priority: drop any pending incidents rather than
			// extract into an already-cancelled context.
			return
		case sig, ok := <-sigs:
			if !ok {
				flush()
				return
			}
			pending[sig.IncidentID] = sig
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(p.cfg.SignalDebounce)
		case <-timer.C:
			flush()
		}
	}
}

func (p *Pipeline) handleSignal(ctx context.Context, sig scorer.Signal) {
	// EdgeScore reads the scorer's own mutex-guarded edgeScores map, so chain
	// extraction (this goroutine) never races the ingest goroutine's writes to
	// edge.Confidence. In production both hold the same value: handleRaw records
	// the score into the scorer and onto the edge via SetEdgeConfidence.
	scoreFn := p.cfg.Scorer.EdgeScore
	result := chain.Extract(p.cfg.Graph, scoreFn, sig.HotNode)
	if len(result.Steps) == 0 {
		return
	}
	result.IncidentID = sig.IncidentID
	result.IncidentLabel = incidentLabel(p.cfg.Graph, sig.HotNode)
	chainMsg, err := types.NewMessage(types.MsgTypeChainResult, result)
	if err == nil {
		p.cfg.Broadcaster.Send(chainMsg)
	}

	if p.cfg.HEC != nil {
		hctx, hcancel := context.WithTimeout(ctx, 5*time.Second)
		if herr := p.cfg.HEC.Send(hctx, result); herr != nil {
			p.cfg.Logger.Warn("hec write-back failed", "err", herr)
		}
		hcancel()
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		p.runNarration(ctx, result)
	}()
	if p.cfg.IntelAgent != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p.runIntel(ctx, result)
		}()
	}
	wg.Wait()
}

// activityEmitter returns an ai.ActivityFunc that stamps each step with the
// incident, agent, a monotonic sequence number, and a wall-clock timestamp,
// then broadcasts it as an agent_activity message. A fresh emitter (with its
// own seq counter) is created per agent call, so concurrent incidents never
// share state. The returned func is driven by a single agent goroutine, so the
// plain int counter needs no synchronization.
func (p *Pipeline) activityEmitter(incidentID, agent string) ai.ActivityFunc {
	seq := 0
	return func(a types.AgentActivityPayload) {
		a.IncidentID = incidentID
		a.Agent = agent
		a.Seq = seq
		a.TS = time.Now().Unix()
		seq++
		msg, err := types.NewMessage(types.MsgTypeAgentActivity, a)
		if err != nil {
			p.cfg.Logger.Warn("encode agent_activity", "err", err)
			return
		}
		p.cfg.Broadcaster.Send(msg)
	}
}

func (p *Pipeline) runNarration(ctx context.Context, result types.ChainResultPayload) {
	nctx, cancel := context.WithTimeout(ctx, p.cfg.NarrationTimeout)
	defer cancel()
	narr, err := p.cfg.Narrator.Narrate(nctx, result, p.activityEmitter(result.IncidentID, "narrator"))
	if err != nil {
		p.cfg.Logger.Warn("narrate", "err", err)
		return
	}
	narr.IncidentID = result.IncidentID
	if msg, err := types.NewMessage(types.MsgTypeNarration, narr); err == nil {
		p.cfg.Broadcaster.Send(msg)
	}
}

func (p *Pipeline) runIntel(ctx context.Context, result types.ChainResultPayload) {
	ictx, cancel := context.WithTimeout(ctx, p.cfg.IntelTimeout)
	defer cancel()
	payload, err := p.cfg.IntelAgent.Enrich(ictx, result, p.activityEmitter(result.IncidentID, "intel"))
	if err != nil {
		p.cfg.Logger.Warn("threat intel", "err", err)
		payload = types.ThreatIntelPayload{
			Status:     "error",
			Summary:    "Threat intel enrichment failed.",
			Techniques: []types.ThreatIntelTechnique{},
		}
	}
	payload.IncidentID = result.IncidentID
	if msg, err := types.NewMessage(types.MsgTypeThreatIntel, payload); err == nil {
		p.cfg.Broadcaster.Send(msg)
	}
}

// edgeUpdate ties a freshly appended edge to the destination node so we can
// broadcast a meaningful graph_update payload (the new edge plus its newest
// endpoint).
type edgeUpdate struct {
	node *types.Node
	edge *types.Edge
}

// parse dispatches to the per-source schema parser. Phase 1: Sysmon only.
func parse(raw splunk.RawEvent) (any, error) {
	switch raw.Kind {
	case splunk.SourceSysmon:
		return schema.ParseSysmon(raw.Raw)
	default:
		return nil, schema.ErrUnsupportedEvent
	}
}

// materialize converts a typed event into one or more graph node+edge pairs.
// Each returned edge has been appended to g; the caller is responsible for
// scoring and broadcasting. Phase 1: Sysmon EID 1 (ProcessCreate) only.
func materialize(g *graph.Graph, ev any) []edgeUpdate {
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
	}
	return nil
}

func processKey(host string, pid int) string {
	return host + ":" + strconv.Itoa(pid)
}

// incidentLabel names an incident by its hot node's host, falling back to the
// node label. Used as the human-readable incident_label on the chain payload.
func incidentLabel(g *graph.Graph, nodeID string) string {
	n := g.Node(nodeID)
	if n == nil {
		return ""
	}
	if h, ok := n.Attrs["host"].(string); ok && h != "" {
		return h
	}
	return n.Label
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
