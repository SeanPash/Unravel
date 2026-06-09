package splunk

import (
	"context"
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
