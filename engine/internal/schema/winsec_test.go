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

func loadRawWinSec(t *testing.T, name string) map[string]any {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	path := filepath.Join(wd, "..", "..", "testdata", "winsec", name)
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

func TestParseLogonSuccess_FromFixture(t *testing.T) {
	got, err := ParseLogonSuccess(loadRawWinSec(t, "eid4624.json"))
	if err != nil {
		t.Fatalf("ParseLogonSuccess: %v", err)
	}
	want := types.LogonSuccess{
		EventID:        "1003241",
		TS:             time.Date(2026, 6, 5, 19, 37, 0, 0, time.UTC),
		Host:           "FILESRV",
		TargetUser:     "jdoe",
		TargetDomain:   "NORTHPOLE",
		TargetSID:      "S-1-5-21-1111111111-2222222222-3333333333-1108",
		TargetLogonID:  "0x4b2901",
		LogonType:      3,
		LogonProcess:   "NtLmSsp ",
		AuthPackage:    "NTLM",
		Workstation:    "WS01",
		IPAddress:      "10.0.0.5",
		IPPort:         49920,
		SubjectUser:    "-",
		SubjectDomain:  "-",
		SubjectLogonID: "0x0",
	}
	if got != want {
		t.Errorf("LogonSuccess mismatch.\n got: %#v\nwant: %#v", got, want)
	}
}

func TestParseLogonFailure_FromFixture(t *testing.T) {
	got, err := ParseLogonFailure(loadRawWinSec(t, "eid4625.json"))
	if err != nil {
		t.Fatalf("ParseLogonFailure: %v", err)
	}
	if got.TargetUser != "administrator" {
		t.Errorf("TargetUser = %q, want %q", got.TargetUser, "administrator")
	}
	if got.LogonType != 3 {
		t.Errorf("LogonType = %d, want 3", got.LogonType)
	}
	if got.Status != "0xC000006D" || got.SubStatus != "0xC000006A" {
		t.Errorf("status/substatus = %q/%q", got.Status, got.SubStatus)
	}
	if got.IPAddress != "10.0.0.5" || got.IPPort != 49911 {
		t.Errorf("src = %s:%d, want 10.0.0.5:49911", got.IPAddress, got.IPPort)
	}
	if got.Host != "FILESRV" {
		t.Errorf("Host = %q, want FILESRV", got.Host)
	}
	if !got.TS.Equal(time.Date(2026, 6, 5, 19, 35, 0, 0, time.UTC)) {
		t.Errorf("TS = %v, want 2026-06-05T19:35:00Z", got.TS)
	}
}

func TestParseSpecialLogon_FromFixture(t *testing.T) {
	got, err := ParseSpecialLogon(loadRawWinSec(t, "eid4672.json"))
	if err != nil {
		t.Fatalf("ParseSpecialLogon: %v", err)
	}
	if got.SubjectUser != "admin" || got.SubjectDomain != "NORTHPOLE" {
		t.Errorf("subject = %s\\%s", got.SubjectDomain, got.SubjectUser)
	}
	if got.Host != "DC01" {
		t.Errorf("Host = %q, want DC01", got.Host)
	}
	if got.Privileges == "" {
		t.Errorf("Privileges empty, want privilege list")
	}
	if got.SubjectSID != "S-1-5-21-1111111111-2222222222-3333333333-500" {
		t.Errorf("SubjectSID = %q", got.SubjectSID)
	}
}

func TestParseKerberosTGT_FromFixture(t *testing.T) {
	got, err := ParseKerberosTGT(loadRawWinSec(t, "eid4768.json"))
	if err != nil {
		t.Fatalf("ParseKerberosTGT: %v", err)
	}
	if got.TargetUser != "jdoe" {
		t.Errorf("TargetUser = %q, want jdoe", got.TargetUser)
	}
	if got.ServiceName != "krbtgt" {
		t.Errorf("ServiceName = %q, want krbtgt", got.ServiceName)
	}
	if got.IPAddress != "::ffff:10.0.0.5" {
		t.Errorf("IPAddress = %q", got.IPAddress)
	}
	if got.TicketEncryption != "0x12" {
		t.Errorf("TicketEncryption = %q, want 0x12", got.TicketEncryption)
	}
	if got.Host != "DC01" {
		t.Errorf("Host = %q, want DC01", got.Host)
	}
}

func TestParseKerberosService_FromFixture(t *testing.T) {
	got, err := ParseKerberosService(loadRawWinSec(t, "eid4769.json"))
	if err != nil {
		t.Fatalf("ParseKerberosService: %v", err)
	}
	if got.ServiceName != "cifs/filesrv.northpole.local" {
		t.Errorf("ServiceName = %q", got.ServiceName)
	}
	if got.TargetUser != "jdoe@NORTHPOLE.LOCAL" {
		t.Errorf("TargetUser = %q", got.TargetUser)
	}
	if got.Status != "0x0" {
		t.Errorf("Status = %q, want 0x0", got.Status)
	}
	if got.Host != "DC01" {
		t.Errorf("Host = %q, want DC01", got.Host)
	}
}

func TestParseWinSec_DispatchesByEventID(t *testing.T) {
	cases := []struct {
		fixture string
		assert  func(t *testing.T, v any)
	}{
		{"eid4624.json", func(t *testing.T, v any) {
			if _, ok := v.(types.LogonSuccess); !ok {
				t.Errorf("eid4624 dispatch returned %T, want LogonSuccess", v)
			}
		}},
		{"eid4625.json", func(t *testing.T, v any) {
			if _, ok := v.(types.LogonFailure); !ok {
				t.Errorf("eid4625 dispatch returned %T, want LogonFailure", v)
			}
		}},
		{"eid4672.json", func(t *testing.T, v any) {
			if _, ok := v.(types.SpecialLogon); !ok {
				t.Errorf("eid4672 dispatch returned %T, want SpecialLogon", v)
			}
		}},
		{"eid4768.json", func(t *testing.T, v any) {
			if _, ok := v.(types.KerberosTGT); !ok {
				t.Errorf("eid4768 dispatch returned %T, want KerberosTGT", v)
			}
		}},
		{"eid4769.json", func(t *testing.T, v any) {
			if _, ok := v.(types.KerberosService); !ok {
				t.Errorf("eid4769 dispatch returned %T, want KerberosService", v)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.fixture, func(t *testing.T) {
			v, err := ParseWinSec(loadRawWinSec(t, tc.fixture))
			if err != nil {
				t.Fatalf("ParseWinSec: %v", err)
			}
			tc.assert(t, v)
		})
	}
}

func TestParseWinSec_UnsupportedEventID(t *testing.T) {
	raw := map[string]any{"EventID": "4634", "_time": "2026-06-05T19:30:00Z", "host": "WS01"}
	_, err := ParseWinSec(raw)
	if !errors.Is(err, ErrUnsupportedEvent) {
		t.Errorf("err = %v, want ErrUnsupportedEvent", err)
	}
}

func TestParseWinSec_MissingEventID(t *testing.T) {
	raw := map[string]any{"_time": "2026-06-05T19:30:00Z", "host": "WS01"}
	_, err := ParseWinSec(raw)
	if err == nil {
		t.Error("expected error for missing EventID")
	}
}
