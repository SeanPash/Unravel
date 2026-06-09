package splunk

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHECClientSend(t *testing.T) {
	type capturedReq struct {
		authHeader  string
		contentType string
		body        map[string]any
	}
	var captured capturedReq

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured.authHeader = r.Header.Get("Authorization")
		captured.contentType = r.Header.Get("Content-Type")
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &captured.body)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"text":"Success","code":0}`))
	}))
	defer srv.Close()

	client, err := NewHECClient(HECConfig{
		URL:        srv.URL,
		Token:      "test-token",
		Index:      "main",
		Sourcetype: "chain_result",
	})
	if err != nil {
		t.Fatalf("NewHECClient: %v", err)
	}

	event := map[string]any{"confidence": 0.91, "steps": []any{}}
	if err := client.Send(context.Background(), event); err != nil {
		t.Fatalf("Send: %v", err)
	}

	if want := "Splunk test-token"; captured.authHeader != want {
		t.Errorf("Authorization header = %q, want %q", captured.authHeader, want)
	}
	if want := "application/json"; captured.contentType != want {
		t.Errorf("Content-Type = %q, want %q", captured.contentType, want)
	}
	if captured.body["index"] != "main" {
		t.Errorf("index = %v, want %q", captured.body["index"], "main")
	}
	if captured.body["sourcetype"] != "chain_result" {
		t.Errorf("sourcetype = %v, want %q", captured.body["sourcetype"], "chain_result")
	}
	if captured.body["event"] == nil {
		t.Error("event field missing from HEC payload")
	}
}

func TestHECClientSendNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	client, err := NewHECClient(HECConfig{URL: srv.URL, Token: "bad-token"})
	if err != nil {
		t.Fatalf("NewHECClient: %v", err)
	}
	if err := client.Send(context.Background(), "ping"); err == nil {
		t.Error("expected error on 403, got nil")
	}
}

func TestNewHECClientValidation(t *testing.T) {
	if _, err := NewHECClient(HECConfig{Token: "tok"}); err == nil {
		t.Error("expected error when URL is empty")
	}
	if _, err := NewHECClient(HECConfig{URL: "http://x"}); err == nil {
		t.Error("expected error when Token is empty")
	}
}
