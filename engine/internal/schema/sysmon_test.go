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

func loadRaw(t *testing.T, name string) map[string]any {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	path := filepath.Join(wd, "..", "..", "testdata", "sysmon", name)
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

func TestParseProcessCreate_FromFixture(t *testing.T) {
	got, err := ParseProcessCreate(loadRaw(t, "eid1.json"))
	if err != nil {
		t.Fatalf("ParseProcessCreate: %v", err)
	}
	want := types.ProcessCreate{
		EventID:     "884213",
		TS:          time.Date(2026, 6, 5, 19, 30, 0, 0, time.UTC),
		Host:        "WS01",
		PID:         4880,
		Image:       `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
		ParentPID:   4120,
		ParentImage: `C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE`,
		CommandLine: "powershell.exe -NoP -W Hidden -Enc YQBiAGMAZA==",
		User:        `NORTHPOLE\jdoe`,
	}
	if got != want {
		t.Errorf("ProcessCreate mismatch.\n got: %#v\nwant: %#v", got, want)
	}
}

func TestParseNetworkConnect_FromFixture(t *testing.T) {
	got, err := ParseNetworkConnect(loadRaw(t, "eid3.json"))
	if err != nil {
		t.Fatalf("ParseNetworkConnect: %v", err)
	}
	if got.PID != 4880 {
		t.Errorf("PID = %d, want 4880", got.PID)
	}
	if got.DstIP != "203.0.113.42" || got.DstPort != 443 {
		t.Errorf("dest = %s:%d, want 203.0.113.42:443", got.DstIP, got.DstPort)
	}
	if got.Protocol != "tcp" {
		t.Errorf("Protocol = %q, want %q", got.Protocol, "tcp")
	}
	if got.Host != "WS01" {
		t.Errorf("Host = %q, want WS01", got.Host)
	}
	if !got.TS.Equal(time.Date(2026, 6, 5, 19, 31, 0, 0, time.UTC)) {
		t.Errorf("TS = %v, want 2026-06-05T19:31:00Z", got.TS)
	}
}

func TestParseProcessAccess_FromFixture(t *testing.T) {
	got, err := ParseProcessAccess(loadRaw(t, "eid10.json"))
	if err != nil {
		t.Fatalf("ParseProcessAccess: %v", err)
	}
	if got.SourcePID != 4880 || got.TargetPID != 688 {
		t.Errorf("PIDs src=%d dst=%d, want 4880/688", got.SourcePID, got.TargetPID)
	}
	if got.TargetImage != `C:\Windows\System32\lsass.exe` {
		t.Errorf("TargetImage = %q", got.TargetImage)
	}
	if got.GrantedAccess != "0x1010" {
		t.Errorf("GrantedAccess = %q, want 0x1010", got.GrantedAccess)
	}
}

func TestParseFileCreate_FromFixture(t *testing.T) {
	got, err := ParseFileCreate(loadRaw(t, "eid11.json"))
	if err != nil {
		t.Fatalf("ParseFileCreate: %v", err)
	}
	if got.PID != 4880 {
		t.Errorf("PID = %d, want 4880", got.PID)
	}
	if got.TargetFilename != `C:\Users\jdoe\AppData\Local\Temp\creds.dmp` {
		t.Errorf("TargetFilename = %q", got.TargetFilename)
	}
}

func TestParseSysmon_DispatchesByEventID(t *testing.T) {
	cases := []struct {
		fixture string
		assert  func(t *testing.T, v any)
	}{
		{"eid1.json", func(t *testing.T, v any) {
			if _, ok := v.(types.ProcessCreate); !ok {
				t.Errorf("eid1 dispatch returned %T, want ProcessCreate", v)
			}
		}},
		{"eid3.json", func(t *testing.T, v any) {
			if _, ok := v.(types.NetworkConnect); !ok {
				t.Errorf("eid3 dispatch returned %T, want NetworkConnect", v)
			}
		}},
		{"eid10.json", func(t *testing.T, v any) {
			if _, ok := v.(types.ProcessAccess); !ok {
				t.Errorf("eid10 dispatch returned %T, want ProcessAccess", v)
			}
		}},
		{"eid11.json", func(t *testing.T, v any) {
			if _, ok := v.(types.FileCreate); !ok {
				t.Errorf("eid11 dispatch returned %T, want FileCreate", v)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.fixture, func(t *testing.T) {
			v, err := ParseSysmon(loadRaw(t, tc.fixture))
			if err != nil {
				t.Fatalf("ParseSysmon: %v", err)
			}
			tc.assert(t, v)
		})
	}
}

func TestParseSysmon_UnsupportedEventID(t *testing.T) {
	raw := map[string]any{"EventID": "7", "_time": "2026-06-05T19:30:00Z", "host": "WS01"}
	_, err := ParseSysmon(raw)
	if !errors.Is(err, ErrUnsupportedEvent) {
		t.Errorf("err = %v, want ErrUnsupportedEvent", err)
	}
}

func TestParseSysmon_MissingEventID(t *testing.T) {
	raw := map[string]any{"_time": "2026-06-05T19:30:00Z", "host": "WS01"}
	_, err := ParseSysmon(raw)
	if err == nil {
		t.Error("expected error for missing EventID")
	}
}

func TestAsInt_HandlesStringAndFloatAndHex(t *testing.T) {
	cases := []struct {
		name string
		raw  map[string]any
		key  string
		want int
	}{
		{"string", map[string]any{"x": "42"}, "x", 42},
		{"float", map[string]any{"x": 42.0}, "x", 42},
		{"hex", map[string]any{"x": "0x1010"}, "x", 0x1010},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := asInt(tc.raw, tc.key)
			if err != nil {
				t.Fatalf("asInt: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %d, want %d", got, tc.want)
			}
		})
	}
}

func TestParseTime_FromEpochFloat(t *testing.T) {
	raw := map[string]any{"_time": 1749152400.5}
	tt, err := parseTime(raw, "")
	if err != nil {
		t.Fatalf("parseTime: %v", err)
	}
	want := time.Unix(1749152400, 500000000).UTC()
	if !tt.Equal(want) {
		t.Errorf("got %v, want %v", tt, want)
	}
}
