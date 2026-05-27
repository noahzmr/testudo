package discovery

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestParseDnsmasqLeases(t *testing.T) {
	in := strings.NewReader(strings.Join([]string{
		"1716800000 d8:3a:dd:12:34:56 192.168.1.10 macbook 01:d8:3a:dd:12:34:56",
		"1716800000 aa:bb:cc:dd:ee:ff 192.168.1.11 * 01:aa:bb:cc:dd:ee:ff", // no hostname
		"garbage line",
		"1716800000 11:22:33:44:55:66 192.168.1.12 printer",
	}, "\n"))
	got := parseDnsmasqLeases(in)
	if got["192.168.1.10"] != "macbook" {
		t.Errorf("192.168.1.10 = %q, want macbook", got["192.168.1.10"])
	}
	if _, ok := got["192.168.1.11"]; ok {
		t.Error("192.168.1.11 should be skipped (hostname '*')")
	}
	if got["192.168.1.12"] != "printer" {
		t.Errorf("192.168.1.12 = %q, want printer", got["192.168.1.12"])
	}
}

func TestParseISCLeases(t *testing.T) {
	in := strings.NewReader(`
lease 192.168.1.50 {
  starts 4 2026/05/27 10:00:00;
  binding state active;
  client-hostname "workstation-7";
}
lease 192.168.1.51 {
  binding state active;
}
`)
	got := parseISCLeases(in)
	if got["192.168.1.50"] != "workstation-7" {
		t.Errorf("192.168.1.50 = %q, want workstation-7", got["192.168.1.50"])
	}
	if _, ok := got["192.168.1.51"]; ok {
		t.Error("192.168.1.51 has no client-hostname, should be skipped")
	}
}

// nbstatResponse builds a minimal NBSTAT node-status reply carrying a single
// name entry, so the parser can be exercised without a live host.
func nbstatResponse(name string, suffix byte, group bool) []byte {
	b := []byte{0, 0, 0x84, 0x00, 0, 0, 0, 1, 0, 0, 0, 0} // header, ancount=1
	b = append(b, 0x20)                                   // encoded-name length
	b = append(b, make([]byte, 32)...)                    // encoded name (skipped)
	b = append(b, 0x00)                                   // root terminator
	b = append(b, 0x00, 0x21)                             // type NBSTAT
	b = append(b, 0x00, 0x01)                             // class IN
	b = append(b, 0, 0, 0, 0)                             // ttl

	rdata := []byte{1} // num_names
	nm := make([]byte, 15)
	for i := range nm {
		nm[i] = ' '
	}
	copy(nm, name)
	rdata = append(rdata, nm...)
	rdata = append(rdata, suffix)
	var flags uint16
	if group {
		flags |= 0x8000
	}
	rdata = append(rdata, byte(flags>>8), byte(flags))

	b = append(b, byte(len(rdata)>>8), byte(len(rdata))) // rdlength
	b = append(b, rdata...)
	return b
}

func TestParseNBStatResponse(t *testing.T) {
	if got := parseNBStatResponse(nbstatResponse("MYHOST", 0x00, false)); got != "MYHOST" {
		t.Errorf("parseNBStatResponse = %q, want MYHOST", got)
	}
	// Group names (e.g. workgroup) must be ignored.
	if got := parseNBStatResponse(nbstatResponse("WORKGROUP", 0x00, true)); got != "" {
		t.Errorf("group name should be ignored, got %q", got)
	}
	// Non-<00> suffix (e.g. file server <20>) is not the workstation name.
	if got := parseNBStatResponse(nbstatResponse("SRV", 0x20, false)); got != "" {
		t.Errorf("non-<00> suffix should be ignored, got %q", got)
	}
	// Truncated/garbage input must not panic and returns "".
	if got := parseNBStatResponse([]byte{0, 0, 0}); got != "" {
		t.Errorf("short packet = %q, want empty", got)
	}
}

func TestBuildNBStatQueryWildcard(t *testing.T) {
	q := buildNBStatQuery()
	// 12-byte header + 1 length + 32 encoded + 1 terminator + 4 (type+class).
	if len(q) != 50 {
		t.Fatalf("query length = %d, want 50", len(q))
	}
	if q[12] != 0x20 {
		t.Errorf("encoded-name length byte = %#x, want 0x20", q[12])
	}
	// "*" encodes to "CK": 0x2A => high nibble 2 -> 'C', low nibble A -> 'K'.
	if q[13] != 'C' || q[14] != 'K' {
		t.Errorf("wildcard encoding = %q%q, want CK", string(q[13]), string(q[14]))
	}
}

func TestResolveReverseDNSDoesNotBumpLiveness(t *testing.T) {
	inv := NewInventory()
	inv.Observe(Device{IP: "192.168.1.5", MAC: "d8:3a:dd:12:34:56", Source: "arp"})
	before := inv.Snapshot()[0].LastSeen
	time.Sleep(2 * time.Millisecond)

	r := newHostnameResolver()
	r.lookupAddr = func(ctx context.Context, addr string) ([]string, error) {
		if addr != "192.168.1.5" {
			t.Errorf("lookupAddr got %q", addr)
		}
		return []string{"host5.lan."}, nil
	}
	r.resolve(context.Background(), inv, hostnameMethods{RDNS: true})

	d := inv.Snapshot()[0]
	if d.Hostname != "host5.lan" {
		t.Errorf("hostname = %q, want host5.lan (trailing dot trimmed)", d.Hostname)
	}
	if !d.LastSeen.Equal(before) {
		t.Error("reverse-DNS resolution must not bump LastSeen (offline hosts still have PTR records)")
	}
}

func TestResolveDHCPLeasePriority(t *testing.T) {
	inv := NewInventory()
	inv.Observe(Device{IP: "192.168.1.10", Source: "arp"})

	r := newHostnameResolver()
	r.leases = map[string]string{"192.168.1.10": "from-lease"}
	r.leasesAt = time.Now() // keep refreshLeases from clobbering the injected map
	r.lookupAddr = func(ctx context.Context, addr string) ([]string, error) {
		t.Error("reverse DNS should not run when a DHCP lease already resolved the name")
		return nil, errors.New("unexpected")
	}
	r.resolve(context.Background(), inv, hostnameMethods{DHCP: true, RDNS: true})

	if got := inv.Snapshot()[0].Hostname; got != "from-lease" {
		t.Errorf("hostname = %q, want from-lease", got)
	}
}

func TestShouldAttemptNegativeCache(t *testing.T) {
	r := newHostnameResolver()
	if !r.shouldAttempt("10.0.0.1") {
		t.Fatal("first attempt should be allowed")
	}
	if r.shouldAttempt("10.0.0.1") {
		t.Error("second attempt within TTL should be suppressed")
	}
}
