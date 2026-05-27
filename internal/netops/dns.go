package netops

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// ResolvConfPath is the canonical resolver config. On systemd-resolved
// systems this is a symlink to /run/systemd/resolve/stub-resolv.conf; writes
// to it are silently overwritten by resolved. SetDNSServers detects this and
// refuses rather than appearing to succeed (see InspectResolvConf).
const ResolvConfPath = "/etc/resolv.conf"

// ResolvConf describes the on-disk state of a resolver config file.
type ResolvConf struct {
	Path       string // path inspected
	Symlink    bool   // true if path is a symlink
	LinkTarget string // symlink target, if any
	Stub       bool   // managed by systemd-resolved (writes are ineffective)
}

// InspectResolvConf reports whether path is a systemd-resolved-managed
// symlink. On most modern distros /etc/resolv.conf is a symlink into
// /run/systemd/resolve/, in which case writing the file has no lasting effect:
// resolved owns the resolver state and must be driven via `resolvectl`.
//
// It takes the path as an argument (rather than hard-coding ResolvConfPath) so
// it is unit-testable against a temp directory.
func InspectResolvConf(path string) ResolvConf {
	rc := ResolvConf{Path: path}
	fi, err := os.Lstat(path)
	if err != nil {
		return rc
	}
	if fi.Mode()&os.ModeSymlink == 0 {
		return rc
	}
	rc.Symlink = true
	target, err := os.Readlink(path)
	if err != nil {
		return rc
	}
	rc.LinkTarget = target
	// systemd-resolved's stub and uplink files both live under
	// /run/systemd/resolve/ (stub-resolv.conf / resolv.conf).
	if strings.Contains(target, "systemd/resolve") || strings.Contains(target, "stub-resolv.conf") {
		rc.Stub = true
	}
	return rc
}

// ListDNSServers parses /etc/resolv.conf and returns nameserver lines.
func (w *Writer) ListDNSServers() ([]string, error) {
	f, err := os.Open(ResolvConfPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "nameserver" {
			out = append(out, fields[1])
		}
	}
	return out, scanner.Err()
}

// SetDNSServers rewrites /etc/resolv.conf with the supplied list. Preserves
// any `search`/`domain`/`options` lines that were already present.
// Caveat: on systemd-resolved systems, /etc/resolv.conf is a symlink to a
// stub - writes either fail (read-only) or are clobbered moments later.
// Caller is expected to surface that error to the operator.
func (w *Writer) SetDNSServers(servers []string) error {
	if !w.AllowWrites {
		return ErrWritesDisabled
	}
	// On systemd-resolved systems, rewriting the stub symlink looks like it
	// works but resolved clobbers it moments later - a silent failure that
	// wastes an operator's debugging time. Refuse with an actionable error
	// instead of pretending the write took effect.
	if rc := InspectResolvConf(ResolvConfPath); rc.Stub {
		return fmt.Errorf("%s is managed by systemd-resolved (symlink -> %s); "+
			"editing it has no effect - set resolvers per-interface with: "+
			"resolvectl dns <iface> %s", ResolvConfPath, rc.LinkTarget, strings.Join(servers, " "))
	}
	// Read existing non-nameserver lines for preservation.
	var preserved []string
	if f, err := os.Open(ResolvConfPath); err == nil {
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := scanner.Text()
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "nameserver ") {
				continue
			}
			preserved = append(preserved, line)
		}
		_ = f.Close()
	}
	var b strings.Builder
	b.WriteString("# Managed by Testudo\n")
	for _, srv := range servers {
		fmt.Fprintf(&b, "nameserver %s\n", srv)
	}
	for _, line := range preserved {
		if strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimSpace(line), "# Managed by Testudo") {
			continue
		}
		b.WriteString(line)
		b.WriteString("\n")
	}
	tmp := ResolvConfPath + ".tmp"
	if err := os.WriteFile(tmp, []byte(b.String()), 0o644); err != nil {
		return fmt.Errorf("write resolv.conf: %w", err)
	}
	if err := os.Rename(tmp, ResolvConfPath); err != nil {
		return fmt.Errorf("rename resolv.conf (may need root/CAP_DAC_OVERRIDE): %w", err)
	}
	return nil
}
