package splunk

import (
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func resultWithText(s string) *mcp.CallToolResult {
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: s}}}
}

func TestParseMCPRowsBareArray(t *testing.T) {
	t.Parallel()
	rows, err := parseMCPRows(resultWithText(`[{"reputation":"malicious","category":"credential-access"}]`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(rows) != 1 || rows[0]["reputation"] != "malicious" {
		t.Errorf("rows = %v", rows)
	}
}

func TestParseMCPRowsResultsWrapper(t *testing.T) {
	t.Parallel()
	rows, err := parseMCPRows(resultWithText(`{"results":[{"EventCode":"4624"},{"EventCode":"4625"}]}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(rows) != 2 || rows[1]["EventCode"] != "4625" {
		t.Errorf("rows = %v", rows)
	}
}

func TestParseMCPRowsEmptyIsNotError(t *testing.T) {
	t.Parallel()
	rows, err := parseMCPRows(resultWithText("   "))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("rows = %v, want empty", rows)
	}
}

func TestParseMCPRowsGarbageIsError(t *testing.T) {
	t.Parallel()
	if _, err := parseMCPRows(resultWithText("not json at all")); err == nil {
		t.Fatal("want error on non-JSON content, got nil")
	}
}
