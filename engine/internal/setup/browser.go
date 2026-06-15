package setup

import (
	"os/exec"
	"runtime"
)

// OpenCommand builds the platform-specific command to open url in the default
// browser, without running it. It is pure so the per-GOOS argv can be unit
// tested. An unsupported GOOS returns nil; callers treat that as "just print the
// URL".
//
//	linux:   xdg-open <url>
//	darwin:  open <url>
//	windows: cmd /c start "" <url>   (the empty "" is the title placeholder;
//	         without it `start` treats a quoted URL as the window title)
func OpenCommand(goos, url string) *exec.Cmd {
	switch goos {
	case "linux":
		return exec.Command("xdg-open", url)
	case "darwin":
		return exec.Command("open", url)
	case "windows":
		return exec.Command("cmd", "/c", "start", "", url)
	default:
		return nil
	}
}

// Open launches the default browser at url for the current platform. It is
// best-effort and non-fatal: an unsupported platform or a missing opener returns
// an error that callers are expected to ignore after printing the URL.
func Open(url string) error {
	cmd := OpenCommand(runtime.GOOS, url)
	if cmd == nil {
		return nil
	}
	return cmd.Start()
}
