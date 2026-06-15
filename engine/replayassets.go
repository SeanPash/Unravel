// Package engine embeds the canned replay fixtures so the installed binary can
// run its demo (replay / ai-off modes) from ANY working directory, not just from
// the engine source tree. Unlike the gitignored UI bundle, testdata is committed,
// so embedding it is reliable on a fresh clone and adds only a few KB.
package engine

import "embed"

// ReplayFS holds the minimum fixtures the replay pipeline reads at runtime: the
// kill-chain timeline (read by the mock source) and the SAIA/enrichment fixtures
// the mock Splunk searcher serves. Test-only fixtures (sysmon, winsec, adaudit,
// intel, ws) are deliberately NOT embedded, so they never ship in the binary.
// The replay intel agent uses the live KEV/NVD source, not disk, so the intel
// fixtures are unnecessary here.
//
//go:embed testdata/chain-phishing-events.json
//go:embed testdata/enrichment/lookup_process_reputation.json
//go:embed testdata/enrichment/get_account_logon_history.json
//go:embed testdata/enrichment/fetch_raw_events.json
var ReplayFS embed.FS
