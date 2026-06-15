// Package mitre is the deterministic ATT&CK layer of the engine. It maps a
// chain step's underlying edge to a technique (Classify) and serves a bundled
// ATT&CK reference snapshot (Lookup). No LLM, no network: this is engine-first
// output that the chain extractor annotates and the threat-intel agent reuses.
package mitre

import "strings"

// Technique is the ATT&CK identity attached to a chain step.
type Technique struct {
	ID     string
	Name   string
	Tactic string
}

// rule matches an edge by kind plus optional lowercase substring hints on the
// source and destination node labels. The first matching rule wins, so more
// specific rules (with hints) must precede generic ones for the same kind.
type rule struct {
	kind    string
	srcHint string
	dstHint string
	tech    Technique
}

var rules = []rule{
	// Phishing entry point: an Office app spawned a script host.
	{"spawned", "winword", "", Technique{"T1566.001", "Spearphishing Attachment", "Initial Access"}},
	{"spawned", "excel", "", Technique{"T1566.001", "Spearphishing Attachment", "Initial Access"}},
	{"spawned", "outlook", "", Technique{"T1566.001", "Spearphishing Attachment", "Initial Access"}},
	// Script-host execution (generic spawn of a shell).
	{"spawned", "", "powershell", Technique{"T1059.001", "PowerShell", "Execution"}},
	{"spawned", "", "cmd.exe", Technique{"T1059.003", "Windows Command Shell", "Execution"}},
	// Credential-dumping tool launched: a process spawned mimikatz to scrape
	// secrets. This is the credential-access beat of the kill chain even when
	// the LSASS read itself is not observed as its own edge.
	{"spawned", "", "mimikatz", Technique{"T1003.001", "LSASS Memory", "Credential Access"}},
	// Lateral movement: remote-execution tooling used to reach another host,
	// e.g. wmic /node:<dc> ... or psexec \\<dc> ...
	{"spawned", "", "wmic", Technique{"T1047", "Windows Management Instrumentation", "Lateral Movement"}},
	{"spawned", "", "psexec", Technique{"T1021.002", "SMB/Windows Admin Shares", "Lateral Movement"}},
	// Credential dumping from LSASS.
	{"dumped_memory_of", "", "lsass", Technique{"T1003.001", "LSASS Memory", "Credential Access"}},
	{"accessed_credential", "", "lsass", Technique{"T1003.001", "LSASS Memory", "Credential Access"}},
	{"accessed_credential", "", "", Technique{"T1003.001", "LSASS Memory", "Credential Access"}},
	// Privileged-account logon outranks generic auth, so it is listed first.
	{"authenticated_as", "", "admin", Technique{"T1078.002", "Domain Accounts", "Privilege Escalation"}},
	// Pass-the-ticket / generic authentication.
	{"authenticated_as", "", "", Technique{"T1550.003", "Pass the Ticket", "Lateral Movement"}},
}

// Classify returns the technique for an edge, or ok=false when no rule matches.
// Matching is case-insensitive on the label hints.
func Classify(edgeKind, srcLabel, dstLabel string) (Technique, bool) {
	src := strings.ToLower(srcLabel)
	dst := strings.ToLower(dstLabel)
	for _, r := range rules {
		if r.kind != edgeKind {
			continue
		}
		if r.srcHint != "" && !strings.Contains(src, r.srcHint) {
			continue
		}
		if r.dstHint != "" && !strings.Contains(dst, r.dstHint) {
			continue
		}
		return r.tech, true
	}
	return Technique{}, false
}
