package mitre

import "testing"

func TestLookupReturnsBundledIntel(t *testing.T) {
	ti, ok := Lookup("T1003.001")
	if !ok {
		t.Fatal("expected T1003.001 in the snapshot")
	}
	if ti.Name == "" || len(ti.Groups) == 0 || len(ti.Software) == 0 || len(ti.Mitigations) == 0 {
		t.Errorf("snapshot entry incomplete: %+v", ti)
	}
	if !containsString(ti.Software, "Mimikatz") {
		t.Errorf("expected Mimikatz among T1003.001 software, got %v", ti.Software)
	}
}

func TestLookupUnknownTechnique(t *testing.T) {
	if _, ok := Lookup("T9999"); ok {
		t.Error("expected unknown technique to miss")
	}
}

func containsString(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}
