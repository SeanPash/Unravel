package ai

import "context"

// SplunkSearcher executes a one-shot SPL query and returns the result rows.
// Implementations: splunk.RESTSearcher (live), splunk.MockSearcher (replay/test).
type SplunkSearcher interface {
	Search(ctx context.Context, query string) ([]map[string]any, error)
}
