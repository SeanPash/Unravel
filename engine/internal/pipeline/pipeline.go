// Package pipeline wires every engine subcomponent into the streaming loop.
// Source -> schema mapper -> graph -> scorer -> (chain extractor + narrator)
// -> WebSocket broadcaster. The scorer's threshold signal is consumed in a
// separate goroutine so chain extraction and the AI call never stall ingest.
package pipeline

import (
	"context"
	"errors"
	"log/slog"
	"regexp"
	"strconv"
	"strings"
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
		if u.authKind != "" {
			p.cfg.Scorer.SetAuthKind(u.edge, u.authKind)
		}
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
		Raw:     sanitizeRaw(raw.Raw),
	})
	if err != nil {
		p.cfg.Logger.Warn("encode log_event", "err", err)
		return
	}
	p.cfg.Broadcaster.Send(msg)
}

// logFieldAllowlist is the set of raw-event fields safe to surface to every
// connected UI client as source-log evidence. Raw Windows logs routinely carry
// credentials (in command lines) and PII; anything not on this list is dropped,
// and CommandLine-style fields are additionally scrubbed for secret patterns.
// Keys are matched against several common TA/CIM aliases so the allowlist holds
// regardless of the upstream field mapping. The values the UI reads
// (timestamp, source, event id, image/process, parent, user, key network
// fields) all map here.
var logFieldAllowlist = []string{
	// identity / routing
	"EventID", "EventCode", "RecordNumber", "host", "ComputerName", "Computer",
	"source", "sourcetype", "Channel",
	// process
	"Image", "process", "process_path", "Process_Name",
	"ParentImage", "parent_process", "parent_process_path",
	"ProcessId", "ParentProcessId",
	// principals
	"User", "user", "TargetUserName", "TargetDomainName", "SubjectUserName",
	"SubjectDomainName", "MemberName", "Account_Name",
	// auth / kerberos
	"LogonType", "AuthenticationPackageName", "LogonProcessName", "ServiceName",
	"Status",
	// AD object change
	"ObjectClass", "ObjectDN", "AttributeLDAPDisplayName",
	// network
	"IpAddress", "src_ip", "src", "IpPort", "DestinationIp", "dest_ip",
	"DestinationPort", "dest_port", "Protocol",
	// command line (scrubbed below, not dropped, since it is core evidence)
	"CommandLine", "process_command_line", "Process_Command_Line",
}

// commandLineKeys names the fields treated as command lines: present in the
// allowlist but redacted for secret patterns rather than passed verbatim.
var commandLineKeys = map[string]bool{
	"CommandLine":          true,
	"process_command_line": true,
	"Process_Command_Line": true,
}

// secretArgPattern matches common credential-bearing argument shapes in command
// lines, e.g. "/user:alice", "-p:hunter2", "/password hunter2",
// "password=hunter2", "token=abc". Both "/" and "-" flag prefixes and ":", "=",
// and whitespace separators are handled. The captured flag (group 1) is
// preserved and the secret value is replaced.
//
// The bare-word credential tokens (password, token, secret, key, ...) are
// anchored at a word boundary so they only fire as standalone argument names,
// not as substrings inside unrelated identifiers. Without the boundary, common
// command text like a registry path ending in "...\MyKey value" or "...Key /v"
// was being shredded because "key" matched mid-word. The flag-prefixed forms
// ([-/]user, -p, ...) keep their leading prefix as the anchor.
//
// The hash-bearing flags (/ntlm, /rc4, /aes256, -hash) are included because the
// engine's own threat scenario is mimikatz pass-the-hash, where the NT hash is
// the credential being passed on the command line; without these the secret
// would survive into broadcast log evidence.
var secretArgPattern = regexp.MustCompile(`(?i)([-/](?:user|u|p|pass|passwd|pwd|password|ntlm|rc4|aes256|hash)|\b(?:password|passwd|pwd|token|secret|apikey|api[-_]?key|key|ntlm|hash))\s*[:=\s]\s*\S+`)

// netUsePassPattern catches the "net use \\host /user:DOMAIN\acct PASSWORD"
// form, where the password is a positional token trailing the /user: argument
// rather than an explicit flag value. The /user: portion (group 1) is kept.
var netUsePassPattern = regexp.MustCompile(`(?i)([-/]user:\S+)\s+\S+`)

// sanitizeRaw returns a field-allowlisted, secret-scrubbed copy of a raw event
// safe to broadcast. Fields not on the allowlist are dropped entirely; command
// lines are kept (they are primary evidence) but have credential-shaped
// arguments redacted.
func sanitizeRaw(raw map[string]any) map[string]any {
	out := make(map[string]any, len(logFieldAllowlist))
	for _, k := range logFieldAllowlist {
		v, ok := raw[k]
		if !ok || v == nil {
			continue
		}
		if commandLineKeys[k] {
			if s, isStr := v.(string); isStr {
				out[k] = redactSecrets(s)
				continue
			}
		}
		out[k] = v
	}
	return out
}

// redactSecrets replaces credential-shaped argument values in a command line
// with [REDACTED] while preserving the surrounding command text (the flag name)
// for analysis. It handles explicit credential flags and the net-use style
// positional password that trails a /user: argument.
func redactSecrets(cmd string) string {
	// Redact a positional password following /user:... but only when the next
	// token is itself not another flag (a following "-x"/"/x" is an option).
	cmd = netUsePassPattern.ReplaceAllStringFunc(cmd, func(m string) string {
		loc := netUsePassPattern.FindStringSubmatchIndex(m)
		if loc == nil || loc[2] < 0 {
			return m
		}
		kept := m[loc[2]:loc[3]]
		trailing := strings.TrimSpace(m[loc[3]:])
		if strings.HasPrefix(trailing, "-") || strings.HasPrefix(trailing, "/") {
			return m // a following option, not a positional password
		}
		return kept + " [REDACTED]"
	})

	return secretArgPattern.ReplaceAllStringFunc(cmd, func(m string) string {
		loc := secretArgPattern.FindStringSubmatchIndex(m)
		if loc == nil || loc[2] < 0 {
			return "[REDACTED]"
		}
		flag := m[loc[2]:loc[3]]
		// Preserve the original separator (":" "=" or a space) for readability.
		sep := strings.TrimSpace(m[loc[3]:])
		switch {
		case strings.HasPrefix(sep, ":"):
			return flag + ":[REDACTED]"
		case strings.HasPrefix(sep, "="):
			return flag + "=[REDACTED]"
		default:
			return flag + " [REDACTED]"
		}
	})
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
// endpoint). authKind, when non-empty, tags an authentication edge with its
// protocol so the scorer's auth-aware frequency term can bucket it; the
// pipeline registers it via Scorer.SetAuthKind before scoring.
type edgeUpdate struct {
	node     *types.Node
	edge     *types.Edge
	authKind string
}

// parse dispatches to the per-source schema parser. Sysmon, Windows Security,
// and AD audit are all wired into the live path.
func parse(raw splunk.RawEvent) (any, error) {
	switch raw.Kind {
	case splunk.SourceSysmon:
		return schema.ParseSysmon(raw.Raw)
	case splunk.SourceWinsec:
		return schema.ParseWinSec(raw.Raw)
	case splunk.SourceADAudit:
		return schema.ParseADAudit(raw.Raw)
	default:
		return nil, schema.ErrUnsupportedEvent
	}
}

// materialize converts a typed event into one or more graph node+edge pairs.
// Each returned edge has been appended to g; the caller is responsible for
// scoring and broadcasting.
//
// Fully wired: Sysmon ProcessCreate (EID 1, spawned edge); Windows Security
// logons (4624/4625/4672/4768/4769, authenticated_as edges); AD object changes
// (4720/4728/4732/5136, accessed_credential edges from actor to principal).
// Sysmon EID 3/10/11 and other WinSec/AD EIDs are parsed but not yet
// materialized; see the per-event TODOs below.
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

	case types.LogonSuccess:
		// 4624: a principal authenticated to a host. user -> host.
		return []edgeUpdate{authEdge(g, e.TargetDomain, e.TargetUser, e.Host, e.TS, e.EventID, logonAuthKind(e.LogonType, e.AuthPackage))}

	case types.LogonFailure:
		// 4625: a failed authentication attempt. Still a user->host auth edge so
		// brute-force fans show up in the graph; tagged "failed" for the scorer.
		return []edgeUpdate{authEdge(g, e.TargetDomain, e.TargetUser, e.Host, e.TS, e.EventID, "failed")}

	case types.SpecialLogon:
		// 4672: privileged logon (admin-equivalent rights assigned at logon).
		return []edgeUpdate{authEdge(g, e.SubjectDomain, e.SubjectUser, e.Host, e.TS, e.EventID, "privileged")}

	case types.KerberosTGT:
		// 4768: Kerberos TGT request. The DC issuing the ticket is the host.
		return []edgeUpdate{authEdge(g, e.TargetDomain, e.TargetUser, e.Host, e.TS, e.EventID, "kerberos-tgt")}

	case types.KerberosService:
		// 4769: Kerberos service ticket request. user -> host (issuing DC).
		return []edgeUpdate{authEdge(g, e.TargetDomain, e.TargetUser, e.Host, e.TS, e.EventID, "kerberos-service")}

	case types.ADEvent:
		return materializeADEvent(g, e)
	}
	// TODO: materialize Sysmon NetworkConnect (EID 3, NetFlow node +
	// connected_to), ProcessAccess (EID 10, dumped_memory_of), and FileCreate
	// (EID 11, read_file) once those node/edge models land.
	return nil
}

// authEdge materializes a user->host authentication: a User node keyed by
// domain\user and a Host node keyed by host, joined by an authenticated_as
// edge. Both endpoints carry a "role" attr the scorer reads for its auth-aware
// frequency term. Returns the edgeUpdate (destination node = the host) plus the
// auth kind so the caller can register it with the scorer.
func authEdge(g *graph.Graph, domain, user, host string, ts time.Time, eventID, authKind string) edgeUpdate {
	userKey := principalKey(domain, user)
	userNode := g.FindOrCreateNode(types.NodeKindUser, userKey, principalLabel(domain, user), map[string]any{
		"role":   "user",
		"domain": domain,
	})
	hostNode := g.FindOrCreateNode(types.NodeKindHost, host, host, map[string]any{
		"role": "host",
		"host": host,
	})
	edge := g.AppendEdge(userNode, hostNode, types.EdgeKindAuthenticatedAs, ts, 0, eventID)
	return edgeUpdate{node: hostNode, edge: edge, authKind: authKind}
}

// materializeADEvent turns an AD object-change event into actor -> principal
// edges. The acting account (Actor) is a User node; the affected principal
// (a user account or a group) is a User node keyed by SID when available so
// repeated touches of the same principal coalesce. The edge kind is
// accessed_credential, the closest existing relationship for "an actor mutated
// a security principal" (e.g. adding a backdoor account to Domain Admins).
// TODO: add a dedicated AD-mutation edge kind to the graph package so creation,
// membership, and attribute changes are distinguishable in the chain narrative.
func materializeADEvent(g *graph.Graph, e types.ADEvent) []edgeUpdate {
	if e.Actor == "" && e.Target == "" {
		return nil
	}
	actor := g.FindOrCreateNode(types.NodeKindUser, principalKey(e.ActorDomain, e.Actor), principalLabel(e.ActorDomain, e.Actor), map[string]any{
		"role":   "user",
		"domain": e.ActorDomain,
	})

	switch e.Operation {
	case "MemberAdded":
		// Actor added Member to group Target. Model the security-relevant edge:
		// the added member principal gains the group's privileges.
		groupKey := e.TargetSID
		if groupKey == "" {
			groupKey = principalKey(e.TargetDomain, e.Target)
		}
		group := g.FindOrCreateNode(types.NodeKindUser, groupKey, e.Target, map[string]any{
			"role":       "group",
			"group_type": e.ObjectType,
		})
		var updates []edgeUpdate
		updates = append(updates, edgeUpdate{node: group, edge: g.AppendEdge(actor, group, types.EdgeKindAccessedCredential, e.TS, 0, e.EventID)})
		if e.Member != "" {
			memberKey := e.MemberSID
			if memberKey == "" {
				memberKey = principalKey("", e.Member)
			}
			member := g.FindOrCreateNode(types.NodeKindUser, memberKey, e.Member, map[string]any{
				"role": "user",
			})
			updates = append(updates, edgeUpdate{node: member, edge: g.AppendEdge(member, group, types.EdgeKindAccessedCredential, e.TS, 0, e.EventID)})
		}
		return updates

	default:
		// Created / Modified / other: actor acted on a target principal.
		targetKey := e.TargetSID
		if targetKey == "" {
			targetKey = principalKey(e.TargetDomain, e.Target)
		}
		target := g.FindOrCreateNode(types.NodeKindUser, targetKey, e.Target, map[string]any{
			"role": "user",
		})
		edge := g.AppendEdge(actor, target, types.EdgeKindAccessedCredential, e.TS, 0, e.EventID)
		return []edgeUpdate{{node: target, edge: edge}}
	}
}

// logonAuthKind derives a coarse auth-protocol tag for the scorer's auth-aware
// frequency term from the Windows LogonType and authentication package.
func logonAuthKind(logonType int, authPackage string) string {
	switch logonType {
	case 2:
		return "interactive"
	case 3:
		return "network"
	case 10:
		return "remote-interactive"
	}
	if authPackage != "" {
		return strings.ToLower(strings.TrimSpace(authPackage))
	}
	return "logon"
}

// principalKey builds a stable node key for a security principal. domain\user
// when a domain is present (case-folded so DOMAIN\User and domain\user
// coalesce), otherwise the bare name.
func principalKey(domain, name string) string {
	name = strings.TrimSpace(name)
	domain = strings.TrimSpace(domain)
	if domain != "" && domain != "-" {
		return strings.ToLower(domain + "\\" + name)
	}
	return strings.ToLower(name)
}

// principalLabel is the human-readable label for a principal node.
func principalLabel(domain, name string) string {
	domain = strings.TrimSpace(domain)
	if domain != "" && domain != "-" {
		return domain + "\\" + name
	}
	return name
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
