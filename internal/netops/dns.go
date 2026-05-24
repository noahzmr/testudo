package netops

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// ResolvConfPath is the canonical resolver config. On systemd-resolved
// systems this is a symlink to /run/systemd/resolve/stub-resolv.conf, in
// which case writes won't behave the way operators expect — we leave the
// detection to the caller.
const ResolvConfPath = "/etc/resolv.conf"

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
// stub — writes either fail (read-only) or are clobbered moments later.
// Caller is expected to surface that error to the operator.
func (w *Writer) SetDNSServers(servers []string) error {
	if !w.AllowWrites {
		return ErrWritesDisabled
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
