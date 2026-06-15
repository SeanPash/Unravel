package setup

import (
	"strings"
	"testing"
)

func TestOpenCommand(t *testing.T) {
	const u = "http://127.0.0.1:8080"
	cases := []struct {
		goos string
		want []string // nil means expect a nil command
	}{
		{"linux", []string{"xdg-open", u}},
		{"darwin", []string{"open", u}},
		{"windows", []string{"cmd", "/c", "start", "", u}},
		{"plan9", nil},
	}
	for _, tc := range cases {
		cmd := OpenCommand(tc.goos, u)
		if tc.want == nil {
			if cmd != nil {
				t.Errorf("OpenCommand(%q) = %v, want nil", tc.goos, cmd.Args)
			}
			continue
		}
		if cmd == nil {
			t.Errorf("OpenCommand(%q) = nil, want %v", tc.goos, tc.want)
			continue
		}
		if strings.Join(cmd.Args, "\x00") != strings.Join(tc.want, "\x00") {
			t.Errorf("OpenCommand(%q).Args = %v, want %v", tc.goos, cmd.Args, tc.want)
		}
	}
}
