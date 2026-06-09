package splunk

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMockSearcherReturnsByToolName(t *testing.T) {
	t.Parallel()
	s := NewMockSearcher("../../testdata")

	cases := []struct {
		query   string
		wantKey string
	}{
		{`search index=threat_intel process_name="lsass.exe" | head 5`, "process_name"},
		{`search index=winsec (EventCode=4624 OR EventCode=4625) Account_Name="administrator" earliest=-24h`, "EventCode"},
		{`search index=* (EventCode=1 OR EventCode=10) | head 10`, "EventCode"},
	}
	for _, tc := range cases {
		rows, err := s.Search(context.Background(), tc.query)
		if err != nil {
			t.Fatalf("query %q: %v", tc.query, err)
		}
		if len(rows) == 0 {
			t.Errorf("query %q: want rows, got none", tc.query)
		}
		if _, ok := rows[0][tc.wantKey]; !ok {
			t.Errorf("query %q: want key %q in first row, got %v", tc.query, tc.wantKey, rows[0])
		}
	}
}

func TestMockSearcherMissingFixtureDirReturnsError(t *testing.T) {
	t.Parallel()
	s := NewMockSearcher("/does/not/exist")
	_, err := s.Search(context.Background(), `search index=threat_intel process_name="lsass.exe"`)
	if err == nil {
		t.Fatal("want error for missing fixture dir, got nil")
	}
}

func TestRESTSearcherReturnsResults(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Errorf("Authorization = %q", got)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		if got := r.FormValue("exec_mode"); got != "oneshot" {
			t.Errorf("exec_mode = %q, want oneshot", got)
		}
		if got := r.FormValue("output_mode"); got != "json" {
			t.Errorf("output_mode = %q, want json", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"results": []map[string]any{
				{"process_name": "lsass.exe", "reputation": "malicious"},
			},
		})
	}))
	defer srv.Close()

	s := NewRESTSearcher(srv.URL, "test-token", false)
	rows, err := s.Search(context.Background(), `search index=threat_intel process_name="lsass.exe" | head 5`)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(rows))
	}
	if rows[0]["reputation"] != "malicious" {
		t.Errorf("reputation = %v, want malicious", rows[0]["reputation"])
	}
}

func TestRESTSearcherReturnsErrorOnNon2xx(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer srv.Close()

	s := NewRESTSearcher(srv.URL, "bad-token", false)
	if _, err := s.Search(context.Background(), "search index=*"); err == nil {
		t.Fatal("want error on 401, got nil")
	}
}
