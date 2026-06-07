package splunk

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
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

	HTTPClient *http.Client

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
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: cfg.Insecure},
			},
		}
	}
	return &RESTSource{
		cfg: cfg,
		out: make(chan RawEvent, 256),
	}
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

func (r *RESTSource) run(ctx context.Context) {
	defer r.wg.Done()
	backoff := r.cfg.InitialBackoff
	for {
		if ctx.Err() != nil {
			return
		}
		err := r.stream(ctx)
		if ctx.Err() != nil {
			return
		}
		// Connection dropped; wait then reconnect.
		_ = err
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
// error. Returns nil only when the connection ends cleanly so the caller can
// distinguish backoff-worthy failures from a clean Close.
func (r *RESTSource) stream(ctx context.Context) error {
	endpoint, err := buildExportURL(r.cfg.BaseURL, r.cfg.Search)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+r.cfg.Token)
	req.Header.Set("Accept", "application/json")

	resp, err := r.cfg.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("splunk export status %d: %s", resp.StatusCode, body)
	}
	return r.readLines(ctx, resp.Body)
}

func (r *RESTSource) readLines(ctx context.Context, body io.Reader) error {
	scanner := bufio.NewScanner(body)
	// Splunk preview rows can be large; bump the buffer past the default 64KB.
	buf := make([]byte, 0, 1<<20)
	scanner.Buffer(buf, 1<<22)
	for scanner.Scan() {
		if ctx.Err() != nil {
			return ctx.Err()
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
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return scanner.Err()
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
	case strings.Contains(hay, "security"):
		return SourceWinsec
	case strings.Contains(hay, "directory-service") || strings.Contains(hay, "adaudit"):
		return SourceADAudit
	}
	return SourceSysmon
}

func buildExportURL(base, search string) (string, error) {
	u, err := url.Parse(base)
	if err != nil {
		return "", fmt.Errorf("parse base url: %w", err)
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/services/search/jobs/export"
	q := u.Query()
	q.Set("output_mode", "json")
	q.Set("search", search)
	u.RawQuery = q.Encode()
	return u.String(), nil
}
