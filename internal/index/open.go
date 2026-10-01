package index

import (
	"os/exec"
	"runtime"
)

// OpenBrowser opens url in the user's default browser, best-effort (a headless
// or restricted environment simply prints the URL, which the caller handles).
func OpenBrowser(url string) error {
	var cmd string
	var args []string
	switch runtime.GOOS {
	case "darwin":
		cmd = "open"
	case "windows":
		cmd = "cmd"
		args = []string{"/c", "start"}
	default: // linux, bsd, ...
		cmd = "xdg-open"
	}
	return exec.Command(cmd, append(args, url)...).Start()
}
