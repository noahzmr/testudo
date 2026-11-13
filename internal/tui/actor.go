package tui

import (
	"os"
	"os/user"
	"sync"
)

var (
	tuiActorOnce sync.Once
	tuiActorName string
)

// tuiActor identifies the human at the terminal for audit rows. The TUI has no
// login of its own - whoever can run it already has the box - so the OS user is
// the identity, prefixed so audit readers can tell a TUI action from a Web UI
// session ("tui:alice" vs "alice").
func tuiActor() string {
	tuiActorOnce.Do(func() {
		name := ""
		if u, err := user.Current(); err == nil && u.Username != "" {
			name = u.Username
		} else if env := os.Getenv("USER"); env != "" {
			name = env
		}
		if name == "" {
			name = "unknown"
		}
		if sudoer := os.Getenv("SUDO_USER"); sudoer != "" && sudoer != name {
			name = sudoer + "(sudo)"
		}
		tuiActorName = "tui:" + name
	})
	return tuiActorName
}
