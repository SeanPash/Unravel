package ai

import "context"

// SplunkSearcher executes a one-shot SPL query and returns the result rows.
// Implementations: splunk.RESTSearcher (live), splunk.MockSearcher (replay/test).
type SplunkSearcher interface {
	Search(ctx context.Context, query string) ([]map[string]any, error)
}

// SPLGenerator is an optional capability a SplunkSearcher may also implement:
// turning a natural-language question into SPL via the Splunk AI Assistant
// (saia_generate_spl). Only splunk.MCPSearcher implements it. The narrator
// offers the splunk_nl_search tool only when the configured Searcher satisfies
// this interface, so the tool appears in live+MCP mode and is absent for
// REST/replay, with no change to the one-method SplunkSearcher seam.
type SPLGenerator interface {
	GenerateSPL(ctx context.Context, question string) (string, error)
}
