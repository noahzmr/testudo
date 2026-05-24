package netops

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// DHCPMode describes how an interface gets its addresses.
type DHCPMode string

const (
	DHCPModeUnknown DHCPMode = ""
	DHCPModeStatic  DHCPMode = "static"
	DHCPModeDHCP    DHCPMode = "dhcp"
)

// ErrDHCPClientMissing means the system has neither dhclient nor dhcpcd on PATH.
var ErrDHCPClientMissing = errors.New("no DHCP client (dhclient/dhcpcd) found on PATH")

// SetIfaceDHCP starts a DHCP client on the named interface. Picks dhclient
// if available, otherwise dhcpcd. A 30-second timeout is applied so a
// non-responsive DHCP server doesn't hang the caller indefinitely.
//
// AllowWrites gates the call, same as every other netops mutation.
func (w *Writer) SetIfaceDHCP(iface string) error {
	if !w.AllowWrites {
		return ErrWritesDisabled
	}
	client, err := pickDHCPClient()
	if err != nil {
		return err
	}
	// Bring the interface up first; DHCP clients refuse to bind otherwise.
	if upErr := w.SetIfaceUp(iface); upErr != nil {
		return fmt.Errorf("ensure %s up: %w", iface, upErr)
	}
	// Best-effort release of any prior lease so the new request gets a
	// fresh OFFER even if the kernel still has the old address attached.
	_ = w.FlushAddrs(iface)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var cmd *exec.Cmd
	switch client {
	case "dhclient":
		cmd = exec.CommandContext(ctx, client, "-1", iface)
	case "dhcpcd":
		cmd = exec.CommandContext(ctx, client, "-1", iface)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w (%s)", client, iface, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// SetIfaceStatic releases any DHCP lease and assigns the supplied static
// CIDR. Any existing addresses on the interface are flushed first.
func (w *Writer) SetIfaceStatic(iface, cidr string) error {
	if !w.AllowWrites {
		return ErrWritesDisabled
	}
	// Best-effort release if a dhclient process is running.
	if path, err := exec.LookPath("dhclient"); err == nil {
		_ = exec.Command(path, "-r", iface).Run()
	}
	if err := w.FlushAddrs(iface); err != nil {
		return fmt.Errorf("flush %s: %w", iface, err)
	}
	if err := w.AddAddr(iface, cidr); err != nil {
		return fmt.Errorf("add addr %s on %s: %w", cidr, iface, err)
	}
	if err := w.SetIfaceUp(iface); err != nil {
		return fmt.Errorf("bring up %s: %w", iface, err)
	}
	return nil
}

// IfaceMode returns the best-guess mode of the interface. The heuristic
// looks for a running dhclient/dhcpcd process bound to iface in /proc; if
// none is found it reports static (assuming the iface has an address) or
// unknown.
func (w *Writer) IfaceMode(iface string) DHCPMode {
	if hasDHCPLeaseFor(iface) {
		return DHCPModeDHCP
	}
	infos, err := w.ListIfaces()
	if err != nil {
		return DHCPModeUnknown
	}
	for _, ifi := range infos {
		if ifi.Name == iface && len(ifi.Addrs) > 0 {
			return DHCPModeStatic
		}
	}
	return DHCPModeUnknown
}

func pickDHCPClient() (string, error) {
	for _, name := range []string{"dhclient", "dhcpcd"} {
		if _, err := exec.LookPath(name); err == nil {
			return name, nil
		}
	}
	return "", ErrDHCPClientMissing
}

// hasDHCPLeaseFor checks for a dhclient lease file referencing the
// interface. Works on Debian/Ubuntu where leases live in
// /var/lib/dhcp/dhclient.<iface>.leases.
func hasDHCPLeaseFor(iface string) bool {
	candidates := []string{
		"/var/lib/dhcp/dhclient." + iface + ".leases",
		"/var/lib/dhcpcd/" + iface + ".lease",
	}
	for _, p := range candidates {
		if _, err := exec.Command("test", "-f", p).Output(); err == nil {
			return true
		}
	}
	return false
}
