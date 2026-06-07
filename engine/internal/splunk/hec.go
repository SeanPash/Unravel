package splunk

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// HECConfig configures the HTTP Event Collector write-back client. Token is
// the required authentication value; when empty NewHECClient returns nil so
// the pipeline can skip the sink entirely.
type HECConfig struct {
	URL        string
	Token      string
	Index      string
	Sourcetype string
	Insecure   bool

	HTTPClient *http.Client
}

// HECClient posts engine-derived events to Splunk's services/collector/event
// endpoint. The zero value is not usable; construct via NewHECClient.
type HECClient struct {
	endpoint   string
	token      string
	index      string
	sourcetype string
	httpClient *http.Client
}

// NewHECClient returns a configured HEC client, or nil when cfg.Token is
// empty. A nil return signals the caller to skip the write-back sink.
func NewHECClient(cfg HECConfig) *HECClient {
	if cfg.Token == "" {
		return nil
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: cfg.Insecure},
			},
		}
	}
	return &HECClient{
		endpoint:   buildHECEndpoint(cfg.URL),
		token:      cfg.Token,
		index:      cfg.Index,
		sourcetype: cfg.Sourcetype,
		httpClient: client,
	}
}

// Send posts a single event to HEC. The wrapper envelope wraps `event` with
// the current unix time plus the configured index and sourcetype.
func (c *HECClient) Send(ctx context.Context, event any) error {
	payload := map[string]any{
		"time":  time.Now().Unix(),
		"event": event,
	}
	if c.index != "" {
		payload["index"] = c.index
	}
	if c.sourcetype != "" {
		payload["sourcetype"] = c.sourcetype
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("hec: marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("hec: build request: %w", err)
	}
	req.Header.Set("Authorization", "Splunk "+c.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("hec: post: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("hec: status %d: %s", resp.StatusCode, snippet)
	}
	return nil
}

func buildHECEndpoint(base string) string {
	trimmed := strings.TrimRight(base, "/")
	if strings.HasSuffix(trimmed, "/services/collector/event") {
		return trimmed
	}
	if strings.HasSuffix(trimmed, "/services/collector") {
		return trimmed + "/event"
	}
	return trimmed + "/services/collector/event"
}
