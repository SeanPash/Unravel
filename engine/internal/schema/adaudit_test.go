package schema

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/luigifernandez/unravel/engine/internal/types"
)

func loadRawADAudit(t *testing.T, name string) map[string]any {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	path := filepath.Join(wd, "..", "..", "testdata", "adaudit", name)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal %s: %v", name, err)
	}
	return m
}

func TestParseUserCreated_FromFixture(t *testing.T) {
	got, err := ParseUserCreated(loadRawADAudit(t, "eid4720.json"))
	if err != nil {
		t.Fatalf("ParseUserCreated: %v", err)
	}
	want := types.ADEvent{
		EventID:      "1003315",
		TS:           time.Date(2026, 6, 5, 19, 42, 0, 0, time.UTC),
		Host:         "DC01",
		ObjectType:   "User",
		Operation:    "Created",
		Target:       "backdoor",
		TargetDomain: "NORTHPOLE",
		TargetSID:    "S-1-5-21-1111111111-2222222222-3333333333-1199",
		Actor:        "admin",
		ActorDomain:  "NORTHPOLE",
		ActorSID:     "S-1-5-21-1111111111-2222222222-3333333333-500",
	}
	if got != want {
		t.Errorf("UserCreated mismatch.\n got: %#v\nwant: %#v", got, want)
	}
}

func TestParseGlobalGroupMemberAdded_FromFixture(t *testing.T) {
	got, err := ParseGlobalGroupMemberAdded(loadRawADAudit(t, "eid4728.json"))
	if err != nil {
		t.Fatalf("ParseGlobalGroupMemberAdded: %v", err)
	}
	if got.ObjectType != "GlobalGroup" {
		t.Errorf("ObjectType = %q, want GlobalGroup", got.ObjectType)
	}
	if got.Operation != "MemberAdded" {
		t.Errorf("Operation = %q, want MemberAdded", got.Operation)
	}
	if got.Target != "Domain Admins" {
		t.Errorf("Target = %q, want Domain Admins", got.Target)
	}
	if got.TargetSID != "S-1-5-21-1111111111-2222222222-3333333333-512" {
		t.Errorf("TargetSID = %q", got.TargetSID)
	}
	if got.Member != "CN=backdoor,CN=Users,DC=northpole,DC=local" {
		t.Errorf("Member = %q", got.Member)
	}
	if got.MemberSID != "S-1-5-21-1111111111-2222222222-3333333333-1199" {
		t.Errorf("MemberSID = %q", got.MemberSID)
	}
	if got.Actor != "admin" {
		t.Errorf("Actor = %q, want admin", got.Actor)
	}
	if got.Host != "DC01" {
		t.Errorf("Host = %q, want DC01", got.Host)
	}
	if !got.TS.Equal(time.Date(2026, 6, 5, 19, 43, 0, 0, time.UTC)) {
		t.Errorf("TS = %v", got.TS)
	}
}

func TestParseLocalGroupMemberAdded_FromFixture(t *testing.T) {
	got, err := ParseLocalGroupMemberAdded(loadRawADAudit(t, "eid4732.json"))
	if err != nil {
		t.Fatalf("ParseLocalGroupMemberAdded: %v", err)
	}
	if got.ObjectType != "LocalGroup" {
		t.Errorf("ObjectType = %q, want LocalGroup", got.ObjectType)
	}
	if got.Operation != "MemberAdded" {
		t.Errorf("Operation = %q, want MemberAdded", got.Operation)
	}
	if got.Target != "Administrators" {
		t.Errorf("Target = %q, want Administrators", got.Target)
	}
	if got.TargetDomain != "Builtin" {
		t.Errorf("TargetDomain = %q, want Builtin", got.TargetDomain)
	}
	if got.Host != "FILESRV" {
		t.Errorf("Host = %q, want FILESRV", got.Host)
	}
	if got.Member != "CN=backdoor,CN=Users,DC=northpole,DC=local" {
		t.Errorf("Member = %q", got.Member)
	}
}

func TestParseDirectoryObjectModified_FromFixture(t *testing.T) {
	got, err := ParseDirectoryObjectModified(loadRawADAudit(t, "eid5136.json"))
	if err != nil {
		t.Fatalf("ParseDirectoryObjectModified: %v", err)
	}
	if got.ObjectType != "user" {
		t.Errorf("ObjectType = %q, want user (from ObjectClass)", got.ObjectType)
	}
	if got.Operation != "Modified" {
		t.Errorf("Operation = %q, want Modified", got.Operation)
	}
	if got.Target != "CN=jdoe,CN=Users,DC=northpole,DC=local" {
		t.Errorf("Target = %q", got.Target)
	}
	if got.Attribute != "servicePrincipalName" {
		t.Errorf("Attribute = %q, want servicePrincipalName", got.Attribute)
	}
	if got.AttributeValue != "HOST/filesrv.northpole.local" {
		t.Errorf("AttributeValue = %q", got.AttributeValue)
	}
	if got.Actor != "admin" {
		t.Errorf("Actor = %q, want admin", got.Actor)
	}
	if got.Host != "DC01" {
		t.Errorf("Host = %q, want DC01", got.Host)
	}
}

func TestParseADAudit_DispatchesByEventID(t *testing.T) {
	cases := []struct {
		fixture string
		assert  func(t *testing.T, v types.ADEvent)
	}{
		{"eid4720.json", func(t *testing.T, v types.ADEvent) {
			if v.ObjectType != "User" || v.Operation != "Created" {
				t.Errorf("eid4720 -> %s/%s, want User/Created", v.ObjectType, v.Operation)
			}
		}},
		{"eid4728.json", func(t *testing.T, v types.ADEvent) {
			if v.ObjectType != "GlobalGroup" || v.Operation != "MemberAdded" {
				t.Errorf("eid4728 -> %s/%s", v.ObjectType, v.Operation)
			}
		}},
		{"eid4732.json", func(t *testing.T, v types.ADEvent) {
			if v.ObjectType != "LocalGroup" || v.Operation != "MemberAdded" {
				t.Errorf("eid4732 -> %s/%s", v.ObjectType, v.Operation)
			}
		}},
		{"eid5136.json", func(t *testing.T, v types.ADEvent) {
			if v.Operation != "Modified" {
				t.Errorf("eid5136 -> %s", v.Operation)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.fixture, func(t *testing.T) {
			v, err := ParseADAudit(loadRawADAudit(t, tc.fixture))
			if err != nil {
				t.Fatalf("ParseADAudit: %v", err)
			}
			ev, ok := v.(types.ADEvent)
			if !ok {
				t.Fatalf("ParseADAudit returned %T, want types.ADEvent", v)
			}
			tc.assert(t, ev)
		})
	}
}

func TestParseADAudit_UnsupportedEventID(t *testing.T) {
	raw := map[string]any{"EventID": "4662", "_time": "2026-06-05T19:30:00Z", "host": "DC01"}
	_, err := ParseADAudit(raw)
	if !errors.Is(err, ErrUnsupportedEvent) {
		t.Errorf("err = %v, want ErrUnsupportedEvent", err)
	}
}

func TestParseADAudit_MissingEventID(t *testing.T) {
	raw := map[string]any{"_time": "2026-06-05T19:30:00Z", "host": "DC01"}
	_, err := ParseADAudit(raw)
	if err == nil {
		t.Error("expected error for missing EventID")
	}
}
