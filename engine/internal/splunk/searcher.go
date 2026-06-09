package splunk

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// RESTSearcher implements ai.SplunkSearcher against a live Splunk instance.
// It uses the oneshot search mode which blocks until results are ready.
type RESTSearcher struct {
	baseURL string
	token   string
	client  *http.Client
}

// NewRESTSearcher returns a RESTSearcher. Set insecure=true to skip TLS
// verification (required for GOAD self-signed certs).
func NewRESTSearcher(baseURL, token string, insecure bool) *RESTSearcher {
	return &RESTSearcher{
		baseURL: baseURL,
		token:   token,
		client: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure},
			},
		},
	}
}

// Search executes query as a blocking oneshot search and returns the result rows.
func (r *RESTSearcher) Search(ctx context.Context, query string) ([]map[string]any, error) {
	endpoint := strings.TrimRight(r.baseURL, "/") + "/services/search/jobs"

	form := url.Values{}
	form.Set("search", query)
	form.Set("exec_mode", "oneshot")
	form.Set("output_mode", "json")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+r.token)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := r.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("splunk search: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read search response: %w", err)
	}
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("splunk search status %d: %s", resp.StatusCode, body)
	}

	var out struct {
		Results []map[string]any `json:"results"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("decode search response: %w", err)
	}
	return out.Results, nil
}
