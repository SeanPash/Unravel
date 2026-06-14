package splunk

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// RESTConfig holds the connection parameters for streaming events out of a
// Splunk search head via the export endpoint.
type RESTConfig struct {
	BaseURL  string
	Token    string
	Search   string
	Insecure bool

	// Earliest and Latest bound the search window. Earliest defaults to "rt"
	// (real-time tail) when empty so a live stream does not replay all history;
	// pass a relative ("-15m") or absolute time to override. Latest is usually
	// left empty (open-ended).
	Earliest string
	Latest   string

	// TLSConfig, when set, is used verbatim for the transport (e.g. a RootCAs
	// pool loaded from a corporate private CA bundle). Insecure still forces
	// InsecureSkipVerify on top of it.
	TLSConfig *tls.Config

	HTTPClient *http.Client

	// Logger receives reconnect/error diagnostics. Defaults to slog.Default.
	Logger *slog.Logger

	// Backoff controls reconnect timing after a dropped connection. Zero values
	// pick sensible defaults in NewRESTSource.
	InitialBackoff time.Duration
	MaxBackoff     time.Duration
}

// RESTSource holds a long-lived HTTP connection to Splunk's export endpoint
// and re-emits each line as a RawEvent. Reconnects on drop with exponential
// backoff capped at MaxBackoff.
type RESTSource struct {
	cfg       RESTConfig
	out       chan RawEvent
	cancel    context.CancelFunc
	closeOnce sync.Once
	wg        sync.WaitGroup

	// lastTS tracks the most recent event _time delivered, so a reconnect
	// resumes with earliest=<lastTS> instead of replaying from the original
	// window. Mutated only inside the single streaming goroutine.
	lastTS time.Time
}

// NewRESTSource builds a RESTSource ready to Start. The Search field is wrapped
// in a saved search-style export call against Splunk's REST API; pass a search
// expression like `search index=sysmon` or a tstats query.
func NewRESTSource(cfg RESTConfig) *RESTSource {
	if cfg.InitialBackoff <= 0 {
		cfg.InitialBackoff = time.Second
	}
	if cfg.MaxBackoff <= 0 {
		cfg.MaxBackoff = 30 * time.Second
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: buildTLSConfig(cfg.TLSConfig, cfg.Insecure),
			},
		}
	}
	return &RESTSource{
		cfg: cfg,
		out: make(chan RawEvent, 256),
	}
}

// buildTLSConfig clones base (or starts empty) and applies InsecureSkipVerify
// when insecure is set. Shared by every Splunk transport so --splunk-ca-cert
// and --splunk-insecure behave identically across REST/HEC/MCP.
func buildTLSConfig(base *tls.Config, insecure bool) *tls.Config {
	var cfg *tls.Config
	if base != nil {
		cfg = base.Clone()
	} else {
		cfg = &tls.Config{}
	}
	if insecure {
		cfg.InsecureSkipVerify = true //nolint:gosec
	}
	return cfg
}

// Events returns the channel the pipeline reads from.
func (r *RESTSource) Events() <-chan RawEvent { return r.out }

// Close signals the streaming goroutine to exit and closes the events channel.
// Safe to call more than once.
func (r *RESTSource) Close() error {
	r.closeOnce.Do(func() {
		if r.cancel != nil {
			r.cancel()
		}
		r.wg.Wait()
		close(r.out)
	})
	return nil
}

// Start launches the streaming goroutine. Returns immediately. Callers must
// invoke Close to release resources.
func (r *RESTSource) Start(parent context.Context) {
	ctx, cancel := context.WithCancel(parent)
	r.cancel = cancel
	r.wg.Add(1)
	go r.run(ctx)
}

// configError marks a non-retryable failure (HTTP 4xx: bad token, bad search,
// missing index). The reconnect loop still backs off so it does not hammer the
// search head, but it logs the cause loudly because a tight retry will never
// recover without operator action.
type configError struct {
	status int
	body   string
}

func (e *configError) Error() string {
	return fmt.Sprintf("splunk export status %d: %s", e.status, e.body)
}

func (r *RESTSource) run(ctx context.Context) {
	defer r.wg.Done()
	backoff := r.cfg.InitialBackoff
	for {
		if ctx.Err() != nil {
			return
		}
		delivered, err := r.stream(ctx)
		if ctx.Err() != nil {
			return
		}
		// A stream that delivered events before dropping is a healthy
		// connection that simply ended; reset backoff so a transient blip does
		// not inflate the reconnect delay.
		if delivered {
			backoff = r.cfg.InitialBackoff
		}
		var cfgErr *configError
		switch {
		case errors.As(err, &cfgErr):
			r.cfg.Logger.Warn("splunk export rejected the request; check token, search, and index (not retrying tightly)",
				"status", cfgErr.status, "body", cfgErr.body, "backoff", backoff)
		case err != nil:
			r.cfg.Logger.Warn("splunk export connection dropped; reconnecting",
				"err", err, "backoff", backoff)
		default:
			r.cfg.Logger.Info("splunk export stream ended; reconnecting", "backoff", backoff)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff *= 2
		if backoff > r.cfg.MaxBackoff {
			backoff = r.cfg.MaxBackoff
		}
	}
}

// stream opens one export connection and pushes parsed events until EOF or
// error. The bool reports whether any event was delivered on this connection.
// A *configError return signals a non-retryable 4xx so run can log it clearly.
func (r *RESTSource) stream(ctx context.Context) (bool, error) {
	earliest := r.cfg.Earliest
	if !r.lastTS.IsZero() {
		// Resume just after the last event we delivered rather than replaying
		// the original window on every reconnect. Use nanosecond precision so
		// the inclusive earliest_time boundary only re-delivers events sharing
		// the exact last-seen timestamp, not the whole trailing second.
		earliest = r.lastTS.UTC().Format(time.RFC3339Nano)
	}
	endpoint, err := buildExportURL(r.cfg.BaseURL, r.cfg.Search, earliest, r.cfg.Latest)
	if err != nil {
		return false, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+r.cfg.Token)
	req.Header.Set("Accept", "application/json")

	resp, err := r.cfg.HTTPClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if resp.StatusCode/100 == 4 {
			return false, &configError{status: resp.StatusCode, body: strings.TrimSpace(string(body))}
		}
		return false, fmt.Errorf("splunk export status %d: %s", resp.StatusCode, body)
	}
	return r.readLines(ctx, resp.Body)
}

func (r *RESTSource) readLines(ctx context.Context, body io.Reader) (bool, error) {
	scanner := bufio.NewScanner(body)
	// Splunk preview rows can be large; bump the buffer past the default 64KB.
	buf := make([]byte, 0, 1<<20)
	scanner.Buffer(buf, 1<<22)
	delivered := false
	for scanner.Scan() {
		if ctx.Err() != nil {
			return delivered, ctx.Err()
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		evt, ok := decodeExportLine(line)
		if !ok {
			continue
		}
		select {
		case r.out <- evt:
			delivered = true
			if evt.TS.After(r.lastTS) {
				r.lastTS = evt.TS
			}
		case <-ctx.Done():
			return delivered, ctx.Err()
		}
	}
	if err := scanner.Err(); err != nil {
		// An oversized line (past the 4MB cap) must not tear down the stream
		// into a reconnect loop; log and treat as a clean end so we resume.
		if errors.Is(err, bufio.ErrTooLong) {
			r.cfg.Logger.Warn("splunk export line exceeded scanner buffer; skipping oversized row", "err", err)
			return delivered, nil
		}
		return delivered, err
	}
	return delivered, nil
}

// decodeExportLine parses one preview row from the export stream. The
// preview/result envelope wraps the actual event under `result`; older
// integrations send the event at the top level.
func decodeExportLine(line string) (RawEvent, bool) {
	var envelope struct {
		Result map[string]any `json:"result"`
	}
	if err := json.Unmarshal([]byte(line), &envelope); err == nil && envelope.Result != nil {
		return wrapEvent(envelope.Result)
	}
	var raw map[string]any
	if err := json.Unmarshal([]byte(line), &raw); err != nil {
		return RawEvent{}, false
	}
	return wrapEvent(raw)
}

func wrapEvent(raw map[string]any) (RawEvent, bool) {
	if len(raw) == 0 {
		return RawEvent{}, false
	}
	ts, err := extractTime(raw)
	if err != nil {
		// Drop malformed rows rather than failing the whole stream.
		return RawEvent{}, false
	}
	return RawEvent{
		Kind: classify(raw),
		TS:   ts,
		Raw:  raw,
	}, true
}

// adObjectEIDs are the AD object-change Event IDs the engine's AD parser
// consumes. These arrive on the WinEventLog:Security channel (not
// Directory-Service), so classify must route them to SourceADAudit by EID even
// though the sourcetype says "security".
var adObjectEIDs = map[string]bool{
	"4720": true, // user account created
	"4728": true, // member added to security-enabled global group
	"4732": true, // member added to security-enabled local group
	"5136": true, // a directory service object was modified
}

// classify infers the SourceKind from the Splunk sourcetype/source fields.
// Falls back to SourceSysmon so an unrecognized event still routes somewhere
// the schema package can attempt to parse.
func classify(raw map[string]any) SourceKind {
	st, _ := raw["sourcetype"].(string)
	src, _ := raw["source"].(string)
	hay := strings.ToLower(st + " " + src)
	switch {
	case strings.Contains(hay, "sysmon"):
		return SourceSysmon
	case strings.Contains(hay, "directory-service") || strings.Contains(hay, "adaudit"):
		return SourceADAudit
	case strings.Contains(hay, "security"):
		// AD object-change EIDs are logged on the Security channel; route them
		// to the AD parser rather than the Windows Security parser.
		if adObjectEIDs[eventID(raw)] {
			return SourceADAudit
		}
		return SourceWinsec
	}
	return SourceSysmon
}

// eventID extracts the Windows Event ID from the common field spellings,
// normalizing numeric values to their string form. Returns "" when absent.
func eventID(raw map[string]any) string {
	for _, key := range []string{"EventID", "EventCode", "event_id"} {
		v, ok := raw[key]
		if !ok || v == nil {
			continue
		}
		switch x := v.(type) {
		case string:
			if s := strings.TrimSpace(x); s != "" {
				return s
			}
		case float64:
			return strconv.FormatInt(int64(x), 10)
		}
	}
	return ""
}

func buildExportURL(base, search, earliest, latest string) (string, error) {
	u, err := url.Parse(base)
	if err != nil {
		return "", fmt.Errorf("parse base url: %w", err)
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/services/search/jobs/export"
	q := u.Query()
	q.Set("output_mode", "json")
	q.Set("search", search)
	if earliest != "" {
		q.Set("earliest_time", earliest)
	}
	if latest != "" {
		q.Set("latest_time", latest)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}
