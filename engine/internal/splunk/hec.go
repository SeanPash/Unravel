// Package splunk holds the Splunk source interface and HEC write-back client.
package splunk

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
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
}

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
	transport := http.DefaultTransport
	if cfg.Insecure {
		transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		}
	}
	return &HECClient{
		cfg:    cfg,
		client: &http.Client{Transport: transport},
		url:    cfg.URL + "/services/collector/event",
	}, nil
}

// hecPayload is the JSON body sent to the HEC endpoint.
type hecPayload struct {
	Index      string `json:"index,omitempty"`
	Sourcetype string `json:"sourcetype,omitempty"`
	Event      any    `json:"event"`
}

// Send marshals event and POSTs it to the HEC endpoint. Returns a non-nil
// error if the server responds with a non-2xx status.
func (h *HECClient) Send(ctx context.Context, event any) error {
	body, err := json.Marshal(hecPayload{
		Index:      h.cfg.Index,
		Sourcetype: h.cfg.Sourcetype,
		Event:      event,
	})
	if err != nil {
		return fmt.Errorf("hec: marshal: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("hec: build request: %w", err)
	}
	req.Header.Set("Authorization", "Splunk "+h.cfg.Token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := h.client.Do(req)
	if err != nil {
		return fmt.Errorf("hec: POST: %w", err)
	}
	resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("hec: server returned %d", resp.StatusCode)
	}
	return nil
}
