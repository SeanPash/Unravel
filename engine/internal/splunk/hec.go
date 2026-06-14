// Package splunk holds the Splunk source interface and HEC write-back client.
package splunk

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"time"
)

// HECConfig configures the Splunk HTTP Event Collector write-back client.
type HECConfig struct {
	// URL is the Splunk HEC base URL, e.g. "https://splunk:8088".
	URL string
	// Token is the HEC token (without the "Splunk " prefix).
	Token string
	// Index is the target Splunk index. Empty means the HEC token's default.
	Index string
	// Sourcetype is the Splunk sourcetype to apply. Empty means the default.
	Sourcetype string
	// Insecure skips TLS certificate verification.
	Insecure bool
	// TLSConfig, when set, supplies a RootCAs pool for a corporate private CA.
	// Insecure still forces InsecureSkipVerify on top of it.
	TLSConfig *tls.Config
	// Logger receives non-2xx response bodies and retry diagnostics. Defaults
	// to slog.Default.
	Logger *slog.Logger
}

// hecMaxAttempts caps the retry budget for a single Send. Includes the first
// try, so a value of 4 means up to 3 retries.
const hecMaxAttempts = 4

// hecClientTimeout bounds each individual HEC POST so a hung search head cannot
// block the pipeline forever.
const hecClientTimeout = 10 * time.Second

// HECClient sends structured events to a Splunk HTTP Event Collector endpoint.
// Construct via NewHECClient; the zero value is not usable.
type HECClient struct {
	cfg    HECConfig
	client *http.Client
	url    string
}

// NewHECClient builds a ready-to-use HECClient. Returns an error if cfg.URL
// or cfg.Token is empty.
func NewHECClient(cfg HECConfig) (*HECClient, error) {
	if cfg.URL == "" {
		return nil, fmt.Errorf("hec: URL is required")
	}
	if cfg.Token == "" {
		return nil, fmt.Errorf("hec: Token is required")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	transport := http.DefaultTransport
	if cfg.Insecure || cfg.TLSConfig != nil {
		transport = &http.Transport{
			TLSClientConfig: buildTLSConfig(cfg.TLSConfig, cfg.Insecure),
		}
	}
	return &HECClient{
		cfg:    cfg,
		client: &http.Client{Transport: transport, Timeout: hecClientTimeout},
		url:    cfg.URL + "/services/collector/event",
	}, nil
}

// hecPayload is the JSON body sent to the HEC endpoint.
type hecPayload struct {
	Index      string `json:"index,omitempty"`
	Sourcetype string `json:"sourcetype,omitempty"`
	Event      any    `json:"event"`
}

// Send marshals event and POSTs it to the HEC endpoint, retrying on 429/5xx
// with exponential backoff (honoring Retry-After when present). Returns a
// non-nil error if every attempt fails or the server responds with a
// non-retryable non-2xx status.
func (h *HECClient) Send(ctx context.Context, event any) error {
	body, err := json.Marshal(hecPayload{
		Index:      h.cfg.Index,
		Sourcetype: h.cfg.Sourcetype,
		Event:      event,
	})
	if err != nil {
		return fmt.Errorf("hec: marshal: %w", err)
	}

	backoff := 500 * time.Millisecond
	var lastErr error
	for attempt := 1; attempt <= hecMaxAttempts; attempt++ {
		status, retryAfter, retryable, err := h.send(ctx, body)
		if err == nil {
			return nil
		}
		lastErr = err
		if !retryable || attempt == hecMaxAttempts {
			return err
		}
		wait := backoff
		if retryAfter > 0 {
			wait = retryAfter
		}
		h.cfg.Logger.Warn("hec write-back failed; retrying", "attempt", attempt, "status", status, "err", err, "backoff", wait)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
		backoff *= 2
	}
	return lastErr
}

// send performs one HEC POST. It returns the HTTP status (0 on transport
// error), the server-requested Retry-After delay (0 when absent), whether the
// failure is worth retrying, and the error (nil on 2xx).
func (h *HECClient) send(ctx context.Context, body []byte) (status int, retryAfterDelay time.Duration, retryable bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.url, bytes.NewReader(body))
	if err != nil {
		return 0, 0, false, fmt.Errorf("hec: build request: %w", err)
	}
	req.Header.Set("Authorization", "Splunk "+h.cfg.Token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := h.client.Do(req)
	if err != nil {
		// Network/transport errors are transient and worth a retry.
		return 0, 0, true, fmt.Errorf("hec: POST: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return resp.StatusCode, 0, false, nil
	}
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	retryable = resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500
	return resp.StatusCode, retryAfter(resp.Header.Get("Retry-After")), retryable, fmt.Errorf("hec: server returned %d: %s", resp.StatusCode, respBody)
}

// retryAfter parses a Retry-After header value expressed as delta seconds.
// Returns 0 when the header is absent or not an integer (HTTP-date form is not
// honored here; the caller falls back to exponential backoff).
func retryAfter(v string) time.Duration {
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(v); err == nil && secs > 0 {
		return time.Duration(secs) * time.Second
	}
	return 0
}
