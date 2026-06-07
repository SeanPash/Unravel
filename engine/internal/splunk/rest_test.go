package splunk

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestRESTSourceStreamsExportLines(t *testing.T) {
	t.Parallel()
	body := strings.Join([]string{
		`{"preview":false,"result":{"_time":"2026-06-05T19:30:00.000+00:00","sourcetype":"XmlWinEventLog:Microsoft-Windows-Sysmon/Operational","EventID":"1"}}`,
		`{"preview":false,"result":{"_time":"2026-06-05T19:30:10.000+00:00","sourcetype":"WinEventLog:Security","EventID":"4624"}}`,
	}, "\n")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/services/search/jobs/export" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		if got := r.URL.Query().Get("output_mode"); got != "json" {
			t.Errorf("output_mode=%s", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	src := NewRESTSource(RESTConfig{
		BaseURL: srv.URL,
		Token:   "test",
		Search:  "search index=sysmon",
	})
	src.Start(context.Background())
	defer src.Close()

	got := drainN(t, src.Events(), 2, 2*time.Second)
	if got[0].Kind != SourceSysmon {
		t.Errorf("first event kind = %s, want sysmon", got[0].Kind)
	}
	if got[1].Kind != SourceWinsec {
		t.Errorf("second event kind = %s, want winsec", got[1].Kind)
	}
}

func TestRESTSourceReconnectsOnDrop(t *testing.T) {
	t.Parallel()
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := hits.Add(1)
		if n == 1 {
			// Close the connection immediately to force a reconnect.
			hj, ok := w.(http.Hijacker)
			if !ok {
				t.Fatal("response writer is not a Hijacker")
			}
			conn, _, err := hj.Hijack()
			if err != nil {
				t.Fatal(err)
			}
			conn.Close()
			return
		}
		_, _ = w.Write([]byte(`{"_time":"2026-06-05T19:30:00.000+00:00","sourcetype":"sysmon","EventID":"1"}` + "\n"))
	}))
	defer srv.Close()

	src := NewRESTSource(RESTConfig{
		BaseURL:        srv.URL,
		Token:          "test",
		Search:         "search index=sysmon",
		InitialBackoff: 5 * time.Millisecond,
		MaxBackoff:     20 * time.Millisecond,
	})
	src.Start(context.Background())
	defer src.Close()

	got := drainN(t, src.Events(), 1, 2*time.Second)
	if len(got) != 1 {
		t.Fatalf("want 1 event after reconnect, got %d", len(got))
	}
	if hits.Load() < 2 {
		t.Fatalf("expected reconnect, hits=%d", hits.Load())
	}
}

func TestClassify(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		raw  map[string]any
		want SourceKind
	}{
		{"sysmon by sourcetype", map[string]any{"sourcetype": "Microsoft-Windows-Sysmon/Operational"}, SourceSysmon},
		{"security channel", map[string]any{"sourcetype": "WinEventLog:Security"}, SourceWinsec},
		{"ad audit", map[string]any{"sourcetype": "WinEventLog:Directory-Service"}, SourceADAudit},
		{"unknown falls back to sysmon", map[string]any{"sourcetype": "weird"}, SourceSysmon},
	}
	for _, tc := range cases {
		if got := classify(tc.raw); got != tc.want {
			t.Errorf("%s: got %s want %s", tc.name, got, tc.want)
		}
	}
}

func drainN(t *testing.T, ch <-chan RawEvent, n int, timeout time.Duration) []RawEvent {
	t.Helper()
	out := make([]RawEvent, 0, n)
	deadline := time.After(timeout)
	for len(out) < n {
		select {
		case e, ok := <-ch:
			if !ok {
				return out
			}
			out = append(out, e)
		case <-deadline:
			t.Fatalf("timed out waiting for %d events, got %d", n, len(out))
		}
	}
	return out
}
