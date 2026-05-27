package netops

import (
	"net"
	"testing"

	"golang.org/x/sys/unix"
)

// ndMsg builds a struct ndmsg header for a fixture.
func ndMsg(family byte, ifindex int32, state uint16, flags byte) []byte {
	b := make([]byte, ndMsgLen)
	b[0] = family
	nlnative.PutUint32(b[4:8], uint32(ifindex))
	nlnative.PutUint16(b[8:10], state)
	b[10] = flags
	return b
}

func TestParseNeighMsg_ReachableV4(t *testing.T) {
	msg := ndMsg(unix.AF_INET, 2, unix.NUD_REACHABLE, 0)
	msg = append(msg, encodeAttr(unix.NDA_DST, net.ParseIP("192.168.1.1").To4())...)
	mac, _ := net.ParseMAC("00:1a:2b:3c:4d:5e")
	msg = append(msg, encodeAttr(unix.NDA_LLADDR, mac)...)

	n, ifindex, ok := parseNeighMsg(msg)
	if !ok {
		t.Fatal("parseNeighMsg returned ok=false for a valid v4 reachable entry")
	}
	if ifindex != 2 {
		t.Errorf("ifindex = %d, want 2", ifindex)
	}
	if n.IP != "192.168.1.1" {
		t.Errorf("IP = %q, want 192.168.1.1", n.IP)
	}
	if n.MAC != "00:1a:2b:3c:4d:5e" {
		t.Errorf("MAC = %q, want 00:1a:2b:3c:4d:5e", n.MAC)
	}
	if n.Family != "ipv4" {
		t.Errorf("Family = %q, want ipv4", n.Family)
	}
	if n.State != "REACHABLE" {
		t.Errorf("State = %q, want REACHABLE", n.State)
	}
	if n.Router {
		t.Errorf("Router = true, want false")
	}
}

func TestParseNeighMsg_StaleV6Router(t *testing.T) {
	msg := ndMsg(unix.AF_INET6, 3, unix.NUD_STALE, unix.NTF_ROUTER)
	msg = append(msg, encodeAttr(unix.NDA_DST, net.ParseIP("fe80::1").To16())...)
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	msg = append(msg, encodeAttr(unix.NDA_LLADDR, mac)...)

	n, _, ok := parseNeighMsg(msg)
	if !ok {
		t.Fatal("parseNeighMsg returned ok=false for a valid v6 stale router entry")
	}
	if n.IP != "fe80::1" {
		t.Errorf("IP = %q, want fe80::1", n.IP)
	}
	if n.Family != "ipv6" {
		t.Errorf("Family = %q, want ipv6", n.Family)
	}
	if n.State != "STALE" {
		t.Errorf("State = %q, want STALE", n.State)
	}
	if !n.Router {
		t.Errorf("Router = false, want true (NTF_ROUTER set)")
	}
}

func TestParseNeighMsg_IncompleteNoLLAddr(t *testing.T) {
	// INCOMPLETE entries carry a destination but no link-layer address.
	msg := ndMsg(unix.AF_INET, 2, unix.NUD_INCOMPLETE, 0)
	msg = append(msg, encodeAttr(unix.NDA_DST, net.ParseIP("192.168.1.99").To4())...)

	n, _, ok := parseNeighMsg(msg)
	if !ok {
		t.Fatal("parseNeighMsg returned ok=false for an incomplete entry with a DST")
	}
	if n.State != "INCOMPLETE" {
		t.Errorf("State = %q, want INCOMPLETE", n.State)
	}
	if n.MAC != "" {
		t.Errorf("MAC = %q, want empty", n.MAC)
	}
}

func TestParseNeighMsg_Truncated(t *testing.T) {
	if _, _, ok := parseNeighMsg([]byte{1, 2, 3}); ok {
		t.Error("parseNeighMsg should reject a truncated header")
	}
	// Header present but no NDA_DST attribute => skipped.
	if _, _, ok := parseNeighMsg(ndMsg(unix.AF_INET, 1, unix.NUD_NOARP, 0)); ok {
		t.Error("parseNeighMsg should skip an entry with no destination address")
	}
}

func TestDuplicateIPs(t *testing.T) {
	tests := []struct {
		name     string
		in       []Neighbour
		wantIPs  []string
		wantMACs map[string][]string
	}{
		{
			name: "no conflict",
			in: []Neighbour{
				{IP: "192.168.1.1", MAC: "aa:aa:aa:aa:aa:aa", Dev: "eth0"},
				{IP: "192.168.1.2", MAC: "bb:bb:bb:bb:bb:bb", Dev: "eth0"},
			},
			wantIPs: nil,
		},
		{
			name: "single conflict two macs",
			in: []Neighbour{
				{IP: "192.168.1.1", MAC: "aa:aa:aa:aa:aa:aa", Dev: "eth0"},
				{IP: "192.168.1.1", MAC: "cc:cc:cc:cc:cc:cc", Dev: "wlan0"},
			},
			wantIPs:  []string{"192.168.1.1"},
			wantMACs: map[string][]string{"192.168.1.1": {"aa:aa:aa:aa:aa:aa", "cc:cc:cc:cc:cc:cc"}},
		},
		{
			name: "incomplete entries ignored",
			in: []Neighbour{
				{IP: "192.168.1.1", MAC: "aa:aa:aa:aa:aa:aa", Dev: "eth0"},
				{IP: "192.168.1.1", MAC: "00:00:00:00:00:00", Dev: "eth0"},
				{IP: "192.168.1.1", MAC: "", Dev: "eth0"},
			},
			wantIPs: nil,
		},
		{
			name: "duplicate same mac is not a conflict",
			in: []Neighbour{
				{IP: "10.0.0.1", MAC: "aa:aa:aa:aa:aa:aa", Dev: "eth0"},
				{IP: "10.0.0.1", MAC: "aa:aa:aa:aa:aa:aa", Dev: "eth1"},
			},
			wantIPs: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DuplicateIPs(tt.in)
			if len(got) != len(tt.wantIPs) {
				t.Fatalf("got %d conflicts %v, want %d (%v)", len(got), got, len(tt.wantIPs), tt.wantIPs)
			}
			for i, ip := range tt.wantIPs {
				if got[i].IP != ip {
					t.Errorf("conflict[%d].IP = %q, want %q", i, got[i].IP, ip)
				}
				if want, ok := tt.wantMACs[ip]; ok {
					if len(got[i].MACs) != len(want) {
						t.Errorf("conflict[%d].MACs = %v, want %v", i, got[i].MACs, want)
						continue
					}
					for j := range want {
						if got[i].MACs[j] != want[j] {
							t.Errorf("conflict[%d].MACs = %v, want %v", i, got[i].MACs, want)
							break
						}
					}
				}
			}
		})
	}
}

func TestUnreachableRatioAndClassify(t *testing.T) {
	ns := []Neighbour{
		{State: "REACHABLE"},
		{State: "REACHABLE"},
		{State: "STALE"},
		{State: "FAILED"},
		{State: "INCOMPLETE"},
	}
	st := ClassifyNeighbours(ns)
	if st.Total != 5 || st.Reachable != 2 || st.Stale != 1 || st.Failed != 1 || st.Incomplete != 1 {
		t.Errorf("ClassifyNeighbours = %+v, unexpected", st)
	}
	ratio, total := UnreachableRatio(ns)
	if total != 5 {
		t.Errorf("total = %d, want 5", total)
	}
	if ratio < 0.39 || ratio > 0.41 { // (1 failed + 1 incomplete) / 5 = 0.4
		t.Errorf("ratio = %f, want ~0.4", ratio)
	}

	if r, total := UnreachableRatio(nil); r != 0 || total != 0 {
		t.Errorf("empty table = (%f,%d), want (0,0)", r, total)
	}
}
