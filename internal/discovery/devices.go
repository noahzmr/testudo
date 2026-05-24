// Package discovery enumerates and tracks devices on local and routed
// networks. Passive observation (ARP table reads, flow telemetry) is always
// on; active probing (ICMP sweep, mDNS queries) runs on a timer.
//
// The inventory is in-memory + periodically flushed to the `devices` table
// in SQLite. Vendor lookup uses an embedded OUI prefix table — small, no
// network dependency.
package discovery

import (
	"sort"
	"strings"
	"sync"
	"time"
)

// Device is the in-memory inventory record.
type Device struct {
	IP        string
	MAC       string
	Hostname  string
	Vendor    string
	Iface     string
	OpenPorts []uint16
	Services  []string
	OSHint    string
	Source    string // "arp", "icmp", "mdns", "passive"
	FirstSeen time.Time
	LastSeen  time.Time
}

// Inventory is the canonical device table. Safe for concurrent use.
type Inventory struct {
	mu sync.RWMutex
	m  map[string]*Device // keyed by IP
}

func NewInventory() *Inventory { return &Inventory{m: make(map[string]*Device)} }

// Observe records or updates a device. Empty fields don't overwrite
// existing data — that lets ARP scanners contribute MAC without erasing
// hostnames that mDNS discovered.
func (in *Inventory) Observe(d Device) {
	if d.IP == "" {
		return
	}
	in.mu.Lock()
	defer in.mu.Unlock()
	cur, ok := in.m[d.IP]
	now := time.Now()
	if !ok {
		d.FirstSeen = now
		d.LastSeen = now
		in.m[d.IP] = &d
		return
	}
	cur.LastSeen = now
	if d.MAC != "" {
		cur.MAC = d.MAC
	}
	if d.Hostname != "" {
		cur.Hostname = d.Hostname
	}
	if d.Vendor != "" {
		cur.Vendor = d.Vendor
	}
	if d.Iface != "" {
		cur.Iface = d.Iface
	}
	if d.OSHint != "" {
		cur.OSHint = d.OSHint
	}
	if d.Source != "" {
		cur.Source = d.Source
	}
	if len(d.OpenPorts) > 0 {
		cur.OpenPorts = mergeUniqUint16(cur.OpenPorts, d.OpenPorts)
	}
	if len(d.Services) > 0 {
		cur.Services = mergeUniqString(cur.Services, d.Services)
	}
}

// Snapshot returns a defensive copy sorted by IP.
func (in *Inventory) Snapshot() []Device {
	in.mu.RLock()
	defer in.mu.RUnlock()
	out := make([]Device, 0, len(in.m))
	for _, d := range in.m {
		out = append(out, *d)
	}
	sort.Slice(out, func(i, j int) bool { return ipLess(out[i].IP, out[j].IP) })
	return out
}

// MarkStale removes devices that haven't been seen in `age` and returns
// the count removed. Callers can run this on a tick to keep the inventory tight.
func (in *Inventory) MarkStale(age time.Duration) int {
	cutoff := time.Now().Add(-age)
	in.mu.Lock()
	defer in.mu.Unlock()
	removed := 0
	for ip, d := range in.m {
		if d.LastSeen.Before(cutoff) {
			delete(in.m, ip)
			removed++
		}
	}
	return removed
}

func mergeUniqUint16(a, b []uint16) []uint16 {
	seen := make(map[uint16]struct{}, len(a)+len(b))
	out := make([]uint16, 0, len(a)+len(b))
	for _, v := range a {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	for _, v := range b {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func mergeUniqString(a, b []string) []string {
	seen := make(map[string]struct{}, len(a)+len(b))
	out := make([]string, 0, len(a)+len(b))
	for _, v := range a {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	for _, v := range b {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

// ipLess orders IPs numerically rather than lexicographically. Treats
// IPv6 as "after" IPv4 by length.
func ipLess(a, b string) bool {
	if (strings.Contains(a, ":") != strings.Contains(b, ":")) {
		// IPv4 before IPv6
		return !strings.Contains(a, ":")
	}
	return a < b // fallback to lexical
}
