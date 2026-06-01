package discovery

import (
	"context"
	"encoding/xml"
	"fmt"
	"net"
	"os/exec"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
)

// NmapAvailable reports whether the nmap binary is on PATH. The on-demand
// target scan (IP / CIDR entered by the operator) degrades gracefully when
// it isn't installed - callers surface a clear "nmap not found" message
// rather than a cryptic exec error.
func NmapAvailable() bool {
	_, err := exec.LookPath("nmap")
	return err == nil
}

// NmapResult summarises one on-demand nmap run over an operator-supplied
// target (a single IP or a CIDR block).
type NmapResult struct {
	Target  string   // the IP / CIDR that was scanned
	Hosts   []Device // hosts found up, already folded into the inventory
	Skipped bool     // true when nmap was unavailable
}

// validateScanTarget accepts a single IP (v4/v6) or a CIDR block and returns
// the canonical form. Anything else is rejected so we never hand free-form
// text to the nmap command line.
func validateScanTarget(target string) (string, error) {
	t := strings.TrimSpace(target)
	if t == "" {
		return "", fmt.Errorf("target required (IP or CIDR)")
	}
	if strings.ContainsAny(t, " \t\n;|&$`") {
		return "", fmt.Errorf("invalid characters in target")
	}
	if _, _, err := net.ParseCIDR(t); err == nil {
		return t, nil
	}
	if ip := net.ParseIP(t); ip != nil {
		return t, nil
	}
	return "", fmt.Errorf("not a valid IP or CIDR: %s", t)
}

// NmapScan runs an on-demand nmap scan against target (a single IP or a CIDR)
// and folds every host that comes back up into the inventory under the "nmap"
// source. It returns a summary of the hosts discovered.
//
// The scan uses nmap's default host discovery (so hosts that drop ICMP are
// still found via ARP / TCP probes on the local link) followed by a fast
// top-ports TCP scan (-F). A per-host timeout bounds the wall-clock cost on
// large CIDRs; the caller's ctx caps the run as a whole.
func (s *Scanner) NmapScan(ctx context.Context, target string) (NmapResult, error) {
	canon, err := validateScanTarget(target)
	if err != nil {
		return NmapResult{}, err
	}
	if !NmapAvailable() {
		return NmapResult{Target: canon, Skipped: true}, fmt.Errorf("nmap not found on PATH")
	}

	// -oX -        : XML to stdout for machine parsing
	// -T4          : faster timing template (LAN-friendly)
	// -F           : fast scan, top 100 TCP ports
	// --host-timeout: don't let one slow host stall a CIDR sweep
	args := []string{
		"-oX", "-",
		"-T4",
		"-F",
		"--host-timeout", "60s",
		canon,
	}
	cmd := exec.CommandContext(ctx, "nmap", args...)
	out, err := cmd.Output()
	if err != nil {
		// ctx cancellation surfaces here too; report it verbatim so the UI
		// can show "scan timed out" rather than a generic failure.
		if ctx.Err() != nil {
			return NmapResult{Target: canon}, fmt.Errorf("nmap scan cancelled: %w", ctx.Err())
		}
		return NmapResult{Target: canon}, fmt.Errorf("nmap failed: %w", err)
	}

	hosts, err := parseNmapXML(out)
	if err != nil {
		return NmapResult{Target: canon}, fmt.Errorf("parse nmap output: %w", err)
	}

	res := NmapResult{Target: canon, Hosts: make([]Device, 0, len(hosts))}
	for _, d := range hosts {
		if d.IP == "" {
			continue
		}
		d.Source = "nmap"
		d.LastSeen = time.Now()
		if s.Inventory != nil {
			s.Inventory.Observe(d)
		}
		res.Hosts = append(res.Hosts, d)
	}
	sort.Slice(res.Hosts, func(i, j int) bool { return ipLess(res.Hosts[i].IP, res.Hosts[j].IP) })
	return res, nil
}

// --- nmap XML decoding -----------------------------------------------------
//
// We decode only the fields Testudo cares about. nmap's schema is large and
// stable; unmarshalling a tight subset keeps us resilient to the parts we
// ignore.

type nmapRun struct {
	XMLName xml.Name   `xml:"nmaprun"`
	Hosts   []nmapHost `xml:"host"`
}

type nmapHost struct {
	Status    nmapStatus    `xml:"status"`
	Addresses []nmapAddress `xml:"address"`
	Hostnames []nmapHost2   `xml:"hostnames>hostname"`
	Ports     []nmapPort    `xml:"ports>port"`
	OS        nmapOS        `xml:"os"`
}

type nmapStatus struct {
	State string `xml:"state,attr"`
}

type nmapAddress struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"` // "ipv4", "ipv6", "mac"
	Vendor   string `xml:"vendor,attr"`
}

type nmapHost2 struct {
	Name string `xml:"name,attr"`
}

type nmapPort struct {
	Protocol string        `xml:"protocol,attr"`
	PortID   string        `xml:"portid,attr"`
	State    nmapPortState `xml:"state"`
}

type nmapPortState struct {
	State string `xml:"state,attr"`
}

type nmapOS struct {
	Matches []nmapOSMatch `xml:"osmatch"`
}

type nmapOSMatch struct {
	Name string `xml:"name,attr"`
}

// parseNmapXML decodes nmap's -oX output into Device records for every host
// reported "up". Closed/filtered ports are dropped; only open TCP ports are
// recorded so they line up with the rest of the inventory's OpenPorts.
func parseNmapXML(data []byte) ([]Device, error) {
	var run nmapRun
	if err := xml.Unmarshal(data, &run); err != nil {
		return nil, err
	}
	out := make([]Device, 0, len(run.Hosts))
	for _, h := range run.Hosts {
		if h.Status.State != "" && h.Status.State != "up" {
			continue
		}
		d := Device{}
		for _, a := range h.Addresses {
			switch a.AddrType {
			case "ipv4", "ipv6":
				if d.IP == "" {
					d.IP = a.Addr
				}
			case "mac":
				d.MAC = strings.ToUpper(a.Addr)
				if a.Vendor != "" {
					d.Vendor = a.Vendor
				} else if v := vendorFor(a.Addr); v != "" {
					d.Vendor = v
				}
				d.MACType = classifyMAC(a.Addr)
			}
		}
		if d.IP == "" {
			continue
		}
		if len(h.Hostnames) > 0 && h.Hostnames[0].Name != "" {
			d.Hostname = h.Hostnames[0].Name
		}
		for _, p := range h.Ports {
			if p.State.State != "open" || p.Protocol != "tcp" {
				continue
			}
			if n, err := strconv.ParseUint(p.PortID, 10, 16); err == nil {
				d.OpenPorts = append(d.OpenPorts, uint16(n))
			}
		}
		slices.Sort(d.OpenPorts)
		if len(h.OS.Matches) > 0 && h.OS.Matches[0].Name != "" {
			d.OSHint = h.OS.Matches[0].Name
		}
		out = append(out, d)
	}
	return out, nil
}
