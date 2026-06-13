package ai

import (
	"encoding/json"
	"fmt"
	"strings"
)

// toolCallActivity maps a tool name and its input to a human sentence and an
// honest source label for the activity feed. The source names what the tool
// actually consults: lookup_process_reputation hits a local Splunk index, not
// an external reputation feed, so it is labeled as such.
func toolCallActivity(tool string, input map[string]any) (label, source string) {
	switch tool {
	case "lookup_process_reputation":
		return fmt.Sprintf("Checking %s against local threat intel", strFromInput(input, "name", "the process")),
			"Splunk threat_intel index"
	case "get_account_logon_history":
		return fmt.Sprintf("Pulling 24h logon history for %s", strFromInput(input, "username", "the account")),
			"Splunk winsec index"
	case "fetch_raw_events":
		return fmt.Sprintf("Fetching raw events for %s", eventIDsLabel(input)), "Splunk"
	case "lookup_technique_intel":
		return fmt.Sprintf("Looking up ATT&CK intel for %s", strFromInput(input, "technique_id", "the technique")),
			"MITRE ATT&CK"
	case "lookup_kev":
		return fmt.Sprintf("Searching CISA KEV for %q", strFromInput(input, "keyword", "")), "CISA KEV"
	case "search_cve":
		return fmt.Sprintf("Searching NVD for %q", strFromInput(input, "keyword", "")), "NVD"
	case "splunk_search":
		return fmt.Sprintf("Running ad-hoc SPL: %s", truncate(strFromInput(input, "spl", "a search"), 80)),
			"Splunk"
	default:
		return "Running " + tool, ""
	}
}

// toolResultActivity summarizes a tool's JSON result into a one-line detail and
// a status ("ok" | "empty" | "error"). Parsing is best-effort: malformed or
// unrecognized output degrades to a neutral "completed" rather than failing.
func toolResultActivity(tool, content string) (detail, status string) {
	var obj map[string]any
	if err := json.Unmarshal([]byte(content), &obj); err != nil {
		return "completed", "ok"
	}
	if e, ok := obj["error"].(string); ok && e != "" {
		return e, "error"
	}
	switch tool {
	case "lookup_process_reputation":
		rows := toSlice(obj["rows"])
		if len(rows) == 0 {
			return "no threat-intel match", "empty"
		}
		first, _ := rows[0].(map[string]any)
		rep, _ := first["reputation"].(string)
		cat, _ := first["category"].(string)
		switch {
		case rep != "" && cat != "":
			return fmt.Sprintf("flagged %s (%s)", rep, cat), "ok"
		case rep != "":
			return fmt.Sprintf("flagged %s", rep), "ok"
		default:
			return fmt.Sprintf("%d threat-intel row(s)", len(rows)), "ok"
		}
	case "get_account_logon_history":
		rows := toSlice(obj["rows"])
		if len(rows) == 0 {
			return "no logon events found", "empty"
		}
		failures := 0
		for _, r := range rows {
			if m, ok := r.(map[string]any); ok {
				if code, _ := m["EventCode"].(string); code == "4625" {
					failures++
				}
			}
		}
		return fmt.Sprintf("%d logon events, %d failure(s)", len(rows), failures), "ok"
	case "fetch_raw_events":
		rows := toSlice(obj["rows"])
		if len(rows) == 0 {
			return "no raw events found", "empty"
		}
		return fmt.Sprintf("%d raw event(s)", len(rows)), "ok"
	case "lookup_technique_intel":
		name, _ := obj["name"].(string)
		groups := toSlice(obj["groups"])
		switch {
		case name != "" && len(groups) > 0:
			return fmt.Sprintf("%s; %d associated group(s)", name, len(groups)), "ok"
		case name != "":
			return name, "ok"
		default:
			return "technique intel returned", "ok"
		}
	case "lookup_kev", "search_cve":
		matches := toSlice(obj["matches"])
		if len(matches) == 0 {
			return "no matches", "empty"
		}
		if first, ok := matches[0].(map[string]any); ok {
			if id, _ := first["id"].(string); id != "" {
				return fmt.Sprintf("%d match(es), e.g. %s", len(matches), id), "ok"
			}
		}
		return fmt.Sprintf("%d match(es)", len(matches)), "ok"
	case "splunk_search":
		rows := toSlice(obj["rows"])
		if len(rows) == 0 {
			return "no results", "empty"
		}
		return fmt.Sprintf("%d result row(s)", len(rows)), "ok"
	default:
		return "completed", "ok"
	}
}

func strFromInput(input map[string]any, key, fallback string) string {
	if s, ok := input[key].(string); ok && s != "" {
		return s
	}
	return fallback
}

// truncate shortens s to at most n runes, appending an ellipsis marker when it
// trims, so long ad-hoc SPL stays readable in the activity feed.
func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "..."
}

func eventIDsLabel(input map[string]any) string {
	ids, _ := input["event_ids"].([]any)
	parts := make([]string, 0, len(ids))
	for _, id := range ids {
		if s, ok := id.(string); ok && s != "" {
			parts = append(parts, s)
		}
	}
	if len(parts) == 0 {
		return "the chain's event codes"
	}
	return "EventCode " + strings.Join(parts, ", ")
}

func toSlice(v any) []any {
	s, _ := v.([]any)
	return s
}
