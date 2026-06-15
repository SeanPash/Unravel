package ai

import (
	"fmt"
	"regexp"
	"strings"
)

// This file holds the provider-neutral SPL safety layer shared by every
// search-running tool. It is independent of the LLM backend, so the same guard
// protects every tool the Gemini narrator and intel agent can call. Keeping it
// separate from the model client makes the security seam easy to audit.

// buildSPL returns the SPL query for a given tool name and input parameters.
func buildSPL(name string, input map[string]any) (string, error) {
	switch name {
	case "lookup_process_reputation":
		n, _ := input["name"].(string)
		if n == "" {
			return "", fmt.Errorf("missing name")
		}
		safe, err := splQuotedValue(n)
		if err != nil {
			return "", fmt.Errorf("invalid process name: %w", err)
		}
		return fmt.Sprintf(
			`search index=threat_intel process_name="%s" | head 5 | fields process_name,reputation,category,source`, safe,
		), nil

	case "get_account_logon_history":
		u, _ := input["username"].(string)
		if u == "" {
			return "", fmt.Errorf("missing username")
		}
		safe, err := splQuotedValue(u)
		if err != nil {
			return "", fmt.Errorf("invalid username: %w", err)
		}
		return fmt.Sprintf(
			`search index=winsec (EventCode=4624 OR EventCode=4625) Account_Name="%s" earliest=-24h | head 20 | fields _time,EventCode,IpAddress,Workstation_Name`, safe,
		), nil

	case "fetch_raw_events":
		ids, _ := input["event_ids"].([]any)
		if len(ids) == 0 {
			return "", fmt.Errorf("missing event_ids")
		}
		parts := make([]string, 0, len(ids))
		for _, id := range ids {
			s, ok := id.(string)
			if !ok || s == "" {
				continue
			}
			// EventCode values are numeric Windows codes; anything else is
			// either malformed or an injection attempt, so reject the whole call.
			if !eventCodePattern.MatchString(s) {
				return "", fmt.Errorf("invalid event_id: %q", s)
			}
			parts = append(parts, "EventCode="+s)
		}
		if len(parts) == 0 {
			return "", fmt.Errorf("no valid event_ids")
		}
		return fmt.Sprintf(
			`search index=* (%s) | head 10 | fields _time,EventCode,host,source,_raw`,
			strings.Join(parts, " OR "),
		), nil

	case "splunk_search":
		spl, _ := input["spl"].(string)
		spl = strings.TrimSpace(spl)
		if spl == "" {
			return "", fmt.Errorf("missing spl")
		}
		if !isReadOnlySPL(spl) {
			return "", fmt.Errorf("refused: only read-only SPL is permitted")
		}
		return spl, nil

	default:
		return "", fmt.Errorf("unknown tool: %s", name)
	}
}

// eventCodePattern matches a bare Windows EventCode (digits only). Used to
// validate event_ids before they are interpolated unquoted into SPL.
var eventCodePattern = regexp.MustCompile(`^[0-9]+$`)

// splQuotedValue prepares an untrusted value for interpolation inside an SPL
// double-quoted term. It rejects characters that could break out of the quote
// or change query semantics, then escapes backslashes and double quotes. The
// chain steps that feed these values are built from attacker-influenced log
// fields (process Image, Account_Name), so a value like x" | delete | search "
// must never reach Splunk verbatim. We reject rather than escape control and
// pipe characters because no legitimate process name or SAM account contains
// them; escaping alone would still be fragile across SPL parser quirks.
func splQuotedValue(v string) (string, error) {
	for _, r := range v {
		switch r {
		case '"', '|', '`', '\n', '\r', '\t', '\x00', '[', ']', '$':
			return "", fmt.Errorf("contains disallowed character %q", string(r))
		}
		if r < 0x20 {
			return "", fmt.Errorf("contains control character")
		}
	}
	// Escape backslashes first, then any remaining quote-like risk. With the
	// rejections above this only neutralizes backslashes, but we keep it
	// explicit as defense-in-depth.
	v = strings.ReplaceAll(v, `\`, `\\`)
	return v, nil
}

// pipeWS matches a pipe followed by any run of whitespace, so SPL command
// boundaries normalize to a bare "|cmd" regardless of spacing.
var pipeWS = regexp.MustCompile(`\|\s+`)

// wsBeforePipe matches any run of whitespace immediately before a pipe, so
// "stats |delete" normalizes the same as "stats|delete".
var wsBeforePipe = regexp.MustCompile(`\s+\|`)

// leadingCmd captures the first bareword of a (sub)search so we can require an
// allowed generating command at the start.
var leadingCmd = regexp.MustCompile(`^([a-z_]+)`)

// readOnlyGenerators are the commands a search (or subsearch) may begin with.
// "search" is implicit when a query starts with a term, but we require it to be
// explicit so the allowlist has a known anchor.
var readOnlyGenerators = map[string]bool{
	"search": true,
	"tstats": true,
	"from":   true,
}

// readOnlyCommands is the curated set of pipe commands permitted after the
// generating command. Everything not in this set (|delete, |collect, |rest,
// |map, |loadjob, |savedsearch, |sendemail, |outputlookup, ...) is rejected.
var readOnlyCommands = map[string]bool{
	"stats":       true,
	"tstats":      true,
	"eventstats":  true,
	"streamstats": true,
	"head":        true,
	"tail":        true,
	"fields":      true,
	"table":       true,
	"where":       true,
	"eval":        true,
	"sort":        true,
	"dedup":       true,
	"rename":      true,
	"top":         true,
	"rare":        true,
	"timechart":   true,
	"chart":       true,
	"fillnull":    true,
	"regex":       true,
	"search":      true,
	"bin":         true,
	"bucket":      true,
	"transaction": true,
	"lookup":      true,
	"makemv":      true,
	"mvexpand":    true,
	"spath":       true,
	"rex":         true,
	"convert":     true,
	"addtotals":   true,
	"untable":     true,
	"xyseries":    true,
}

// subsearchPattern finds bracketed subsearches so their contents can be
// validated against the same allowlist.
var subsearchPattern = regexp.MustCompile(`\[([^\[\]]*)\]`)

// isReadOnlySPL enforces an allowlist policy: the query (and every bracketed
// subsearch within it) must begin with an allowed generating command and may
// only chain commands from a curated read-only set. Anything else is rejected.
// This replaces the previous denylist, which missed side-effecting commands
// like |rest, |map, |loadjob, |sendemail and subsearch-embedded deletes. The
// Splunk MCP Server also validates input; this guard is defense-in-depth at the
// AI seam so neither the model nor injected log data can drive a destructive or
// management-API search through any tool. Be conservative: when in doubt, reject.
func isReadOnlySPL(spl string) bool {
	// Reject backticks outright. A backtick in SPL is either a macro invocation
	// (`macro(args)`) or a comment (```...```). A macro expands to arbitrary SPL
	// AFTER this guard runs, so `mymacro` could expand to "| delete" and defeat
	// the entire allowlist; we can only see the pre-expansion token, so we must
	// refuse it. No legitimate read-only query the narrator builds needs a macro
	// (splQuotedValue already strips backticks from interpolated values), so this
	// costs nothing and closes the one hole the allowlist cannot otherwise see.
	if strings.ContainsRune(spl, '`') {
		return false
	}
	// Validate any subsearches first, then strip them so the outer pipeline can
	// be checked without their brackets confusing segment splitting.
	for {
		m := subsearchPattern.FindStringSubmatchIndex(spl)
		if m == nil {
			break
		}
		inner := spl[m[2]:m[3]]
		if !readOnlyPipeline(inner) {
			return false
		}
		spl = spl[:m[0]] + " " + spl[m[1]:]
	}
	return readOnlyPipeline(spl)
}

// readOnlyPipeline validates a single pipeline (no remaining brackets): it must
// start with an allowed generating command and every subsequent "| cmd" segment
// must be in the read-only allowlist.
func readOnlyPipeline(spl string) bool {
	normalized := strings.ToLower(strings.TrimSpace(spl))
	if normalized == "" {
		// An empty (sub)search is harmless.
		return true
	}
	// Normalize whitespace on both sides of pipes so "stats | delete",
	// "stats |delete", and "stats|  delete" all split identically.
	normalized = wsBeforePipe.ReplaceAllString(normalized, "|")
	normalized = pipeWS.ReplaceAllString(normalized, "|")

	segments := strings.Split(normalized, "|")
	for i, seg := range segments {
		seg = strings.TrimSpace(seg)
		if seg == "" {
			// Empty leading segment means the query started with a pipe, e.g.
			// "| tstats ...". The command is then the next segment, so skip.
			if i == 0 {
				continue
			}
			return false
		}
		cmdMatch := leadingCmd.FindStringSubmatch(seg)
		if cmdMatch == nil {
			// A non-piped first segment that does not start with a bareword
			// command (it starts with a search term). Require an explicit
			// generating command instead of relying on implicit search.
			return false
		}
		cmd := cmdMatch[1]
		isFirstCommand := (i == 0) || (i == 1 && strings.TrimSpace(segments[0]) == "")
		if isFirstCommand {
			if !readOnlyGenerators[cmd] {
				return false
			}
			continue
		}
		if !readOnlyCommands[cmd] {
			return false
		}
	}
	return true
}
