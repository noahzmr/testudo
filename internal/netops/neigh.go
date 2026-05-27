package netops

import (
	"fmt"
	"net"
	"sort"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// Neighbour is one entry from the kernel neighbour table (ARP for IPv4, NDP
// for IPv6), denormalised for display and analysis. It is the netlink
// successor to the old /proc/net/arp parse: it covers IPv6, carries the
// resolution state the proc file hides, and feeds duplicate-IP detection.
type Neighbour struct {
	IP     string `json:"ip"`
	MAC    string `json:"mac"`
	Dev    string `json:"dev"`
	Family string `json:"family"` // ipv4 / ipv6
	// State is the kernel NUD state: REACHABLE / STALE / DELAY / PROBE /
	// FAILED / INCOMPLETE / PERMANENT / NOARP / NONE.
	State  string `json:"state"`
	Router bool   `json:"router"` // NDP: neighbour advertised itself as a router
}

// IPConflict reports one IP address answered by more than one MAC across the
// neighbour table - the classic duplicate-IP / rogue-device signature. It is
// a hard local-network fault: two hosts fighting over an address means
// intermittent, direction-dependent connectivity loss.
type IPConflict struct {
	IP   string   `json:"ip"`
	MACs []string `json:"macs"`
	Devs []string `json:"devs"`
}

// NeighStats summarises neighbour-table health for grading and display.
type NeighStats struct {
	Total      int
	Reachable  int
	Stale      int
	Failed     int
	Incomplete int
}

// ndMsgLen is sizeof(struct ndmsg): family(1) pad(3) ifindex(4) state(2)
// flags(1) type(1).
const ndMsgLen = 12

// ListNeighbours dumps the kernel neighbour table for both address families
// via RTNETLINK RTM_GETNEIGH (FAMILY_ALL), returning ARP and NDP entries in
// one pass. The pure decode lives in parseNeighMsg; this method only handles
// the socket and the ifindex->name resolution the parser can't do.
func (w *Writer) ListNeighbours() ([]Neighbour, error) {
	c, err := netlink.Dial(unix.NETLINK_ROUTE, nil)
	if err != nil {
		return nil, fmt.Errorf("netlink dial: %w", err)
	}
	defer c.Close()

	req := make([]byte, ndMsgLen)
	req[0] = unix.AF_UNSPEC // FAMILY_ALL: both ARP (v4) and NDP (v6)

	resp, err := c.Execute(netlink.Message{
		Header: netlink.Header{
			Type:  netlink.HeaderType(unix.RTM_GETNEIGH),
			Flags: netlink.Request | netlink.Dump,
		},
		Data: req,
	})
	if err != nil {
		return nil, fmt.Errorf("rtm_getneigh dump: %w", err)
	}

	idxName := ifIndexNames()
	out := make([]Neighbour, 0, len(resp))
	for _, m := range resp {
		n, ifindex, ok := parseNeighMsg(m.Data)
		if !ok {
			continue
		}
		n.Dev = idxName[ifindex]
		out = append(out, n)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Dev != out[j].Dev {
			return out[i].Dev < out[j].Dev
		}
		return out[i].IP < out[j].IP
	})
	return out, nil
}

// parseNeighMsg decodes one RTM_NEWNEIGH payload (struct ndmsg + attributes)
// into a Neighbour plus its interface index. Pure over bytes so it unit-tests
// against captured fixtures without a kernel. ok=false when the message is
// truncated or carries no destination address.
func parseNeighMsg(data []byte) (n Neighbour, ifindex int, ok bool) {
	if len(data) < ndMsgLen {
		return Neighbour{}, 0, false
	}
	family := data[0]
	ifindex = int(int32(nlnative.Uint32(data[4:8])))
	state := nlnative.Uint16(data[8:10])
	flags := data[10]

	switch family {
	case unix.AF_INET:
		n.Family = "ipv4"
	case unix.AF_INET6:
		n.Family = "ipv6"
	default:
		n.Family = fmt.Sprintf("af-%d", family)
	}
	n.State = neighStateName(state)
	n.Router = flags&unix.NTF_ROUTER != 0

	for _, a := range walkAttrs(data[ndMsgLen:]) {
		switch a.Type {
		case unix.NDA_DST:
			if ip := net.IP(a.Data); len(a.Data) == net.IPv4len || len(a.Data) == net.IPv6len {
				n.IP = ip.String()
			}
		case unix.NDA_LLADDR:
			if len(a.Data) > 0 {
				n.MAC = net.HardwareAddr(a.Data).String()
			}
		}
	}
	if n.IP == "" {
		return Neighbour{}, 0, false
	}
	return n, ifindex, true
}

// neighStateName maps the NUD_* bitmask to a human label. The kernel sets a
// single state bit in practice; the ordering here picks the operationally
// most significant bit if more than one is set.
func neighStateName(s uint16) string {
	switch {
	case s&unix.NUD_INCOMPLETE != 0:
		return "INCOMPLETE"
	case s&unix.NUD_FAILED != 0:
		return "FAILED"
	case s&unix.NUD_REACHABLE != 0:
		return "REACHABLE"
	case s&unix.NUD_STALE != 0:
		return "STALE"
	case s&unix.NUD_DELAY != 0:
		return "DELAY"
	case s&unix.NUD_PROBE != 0:
		return "PROBE"
	case s&unix.NUD_PERMANENT != 0:
		return "PERMANENT"
	case s&unix.NUD_NOARP != 0:
		return "NOARP"
	default:
		return "NONE"
	}
}

// DuplicateIPs returns every IP answered by more than one distinct MAC -
// conflict / rogue-device candidates. Incomplete entries (no/zero MAC) are
// ignored: they're unanswered lookups, not conflicting answers. Pure function
// over the decoded slice, table-testable.
func DuplicateIPs(ns []Neighbour) []IPConflict {
	type agg struct {
		macs    map[string]bool
		devs    map[string]bool
		macList []string
		devList []string
	}
	byIP := map[string]*agg{}
	for _, n := range ns {
		if n.MAC == "" || n.MAC == "00:00:00:00:00:00" {
			continue
		}
		a := byIP[n.IP]
		if a == nil {
			a = &agg{macs: map[string]bool{}, devs: map[string]bool{}}
			byIP[n.IP] = a
		}
		if !a.macs[n.MAC] {
			a.macs[n.MAC] = true
			a.macList = append(a.macList, n.MAC)
		}
		if n.Dev != "" && !a.devs[n.Dev] {
			a.devs[n.Dev] = true
			a.devList = append(a.devList, n.Dev)
		}
	}
	var out []IPConflict
	for ip, a := range byIP {
		if len(a.macList) < 2 {
			continue
		}
		sort.Strings(a.macList)
		sort.Strings(a.devList)
		out = append(out, IPConflict{IP: ip, MACs: a.macList, Devs: a.devList})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IP < out[j].IP })
	return out
}

// ClassifyNeighbours tallies neighbours by resolution state.
func ClassifyNeighbours(ns []Neighbour) NeighStats {
	var st NeighStats
	for _, n := range ns {
		st.Total++
		switch n.State {
		case "REACHABLE", "PERMANENT", "NOARP":
			st.Reachable++
		case "STALE", "DELAY", "PROBE":
			st.Stale++
		case "FAILED":
			st.Failed++
		case "INCOMPLETE":
			st.Incomplete++
		}
	}
	return st
}

// UnreachableRatio is the share of neighbours the kernel currently cannot
// resolve (FAILED + INCOMPLETE) over the total. A failed gateway neighbour is
// imminent connectivity loss, so this feeds the Stability sub-score. Returns
// (0, 0) for an empty table so a host with no neighbours maps to neutral.
func UnreachableRatio(ns []Neighbour) (ratio float64, total int) {
	st := ClassifyNeighbours(ns)
	if st.Total == 0 {
		return 0, 0
	}
	return float64(st.Failed+st.Incomplete) / float64(st.Total), st.Total
}

// ifIndexNames builds an ifindex->name map so the neighbour dump can label
// each entry with its egress device. Best-effort: on error the map is empty
// and Dev fields are left blank.
func ifIndexNames() map[int]string {
	out := map[int]string{}
	ifs, err := net.Interfaces()
	if err != nil {
		return out
	}
	for _, ifi := range ifs {
		out[ifi.Index] = ifi.Name
	}
	return out
}
