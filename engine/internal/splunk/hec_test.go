package splunk

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNewHECClientNilWhenTokenEmpty(t *testing.T) {
	t.Parallel()
	if c := NewHECClient(HECConfig{URL: "https://example", Token: ""}); c != nil {
		t.Fatalf("expected nil client when token is empty, got %#v", c)
	}
}

func TestHECClientSend(t *testing.T) {
	t.Parallel()

	type capture struct {
		path string
		auth string
		body map[string]any
	}
	got := make(chan capture, 1)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read body: %v", err)
		}
		var body map[string]any
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Errorf("unmarshal body: %v", err)
		}
		got <- capture{path: r.URL.Path, auth: r.Header.Get("Authorization"), body: body}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"text":"Success","code":0}`))
	}))
	defer srv.Close()

	client := NewHECClient(HECConfig{
		URL:        srv.URL,
		Token:      "secret-token",
		Index:      "main",
		Sourcetype: "unravel:chain",
	})
	if client == nil {
		t.Fatal("expected non-nil client")
	}

	event := map[string]any{"summary": "phishing chain", "steps": 5}
	if err := client.Send(context.Background(), event); err != nil {
		t.Fatalf("send: %v", err)
	}

	select {
	case c := <-got:
		if c.path != "/services/collector/event" {
			t.Errorf("path = %q, want /services/collector/event", c.path)
		}
		if c.auth != "Splunk secret-token" {
			t.Errorf("auth = %q, want %q", c.auth, "Splunk secret-token")
		}
		if c.body["index"] != "main" {
			t.Errorf("index = %v, want main", c.body["index"])
		}
		if c.body["sourcetype"] != "unravel:chain" {
			t.Errorf("sourcetype = %v, want unravel:chain", c.body["sourcetype"])
		}
		if _, ok := c.body["time"]; !ok {
			t.Error("body missing time field")
		}
		ev, ok := c.body["event"].(map[string]any)
		if !ok {
			t.Fatalf("event field is %T, want map", c.body["event"])
		}
		if ev["summary"] != "phishing chain" {
			t.Errorf("event.summary = %v", ev["summary"])
		}
	default:
		t.Fatal("server handler did not record a request")
	}
}

func TestHECClientSendNon2xx(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"text":"Invalid token"}`))
	}))
	defer srv.Close()

	client := NewHECClient(HECConfig{URL: srv.URL, Token: "bad"})
	err := client.Send(context.Background(), map[string]any{"k": "v"})
	if err == nil {
		t.Fatal("expected error on 401")
	}
	if !strings.Contains(err.Error(), "401") {
		t.Errorf("error = %v, want status 401", err)
	}
}

func TestHECEndpointBuilder(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"https://splunk:8088":                              "https://splunk:8088/services/collector/event",
		"https://splunk:8088/":                             "https://splunk:8088/services/collector/event",
		"https://splunk:8088/services/collector":           "https://splunk:8088/services/collector/event",
		"https://splunk:8088/services/collector/event":     "https://splunk:8088/services/collector/event",
		"https://splunk:8088/services/collector/event/":    "https://splunk:8088/services/collector/event",
	}
	for in, want := range cases {
		if got := buildHECEndpoint(in); got != want {
			t.Errorf("buildHECEndpoint(%q) = %q, want %q", in, got, want)
		}
	}
}
