package mitre

import "testing"

func TestClassifyKnownEdges(t *testing.T) {
	cases := []struct {
		name              string
		kind, src, dst    string
		wantID, wantTactic string
	}{
		{"office macro", "spawned", "WINWORD.EXE", "powershell.exe", "T1566.001", "Initial Access"},
		{"powershell exec", "spawned", "cmd.exe", "powershell.exe", "T1059.001", "Execution"},
		{"lsass dump", "dumped_memory_of", "powershell.exe", "lsass.exe", "T1003.001", "Credential Access"},
		{"cred access lsass", "accessed_credential", "powershell.exe", "lsass.exe", "T1003.001", "Credential Access"},
		{"pass the ticket", "authenticated_as", "user-svc", "DC01", "T1550.003", "Lateral Movement"},
		{"domain admin logon", "authenticated_as", "host", "NORTHPOLE\\Administrator", "T1078.002", "Privilege Escalation"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := Classify(c.kind, c.src, c.dst)
			if !ok {
				t.Fatalf("Classify(%q,%q,%q) returned ok=false", c.kind, c.src, c.dst)
			}
			if got.ID != c.wantID || got.Tactic != c.wantTactic {
				t.Errorf("got {%s,%s}, want {%s,%s}", got.ID, got.Tactic, c.wantID, c.wantTactic)
			}
		})
	}
}

func TestClassifyUnmapped(t *testing.T) {
	if _, ok := Classify("read_file", "notepad.exe", "notes.txt"); ok {
		t.Error("expected read_file to be unmapped")
	}
}
