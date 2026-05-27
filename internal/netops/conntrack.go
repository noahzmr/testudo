package netops

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"sort"
	"strings"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// ConntrackFlow is one live entry from the kernel nf_conntrack table. The
// original tuple is the connection as the initiator sees it; the reply tuple
// is what comes back - they differ once NAT rewrites the addresses or ports,
// which is exactly the "where did my translated flow go" visibility the NAT
// tab lacked. Packets/Bytes sum both directions; 0 when nf_conntrack_acct is
// off.
type ConntrackFlow struct {
	Proto      string `json:"proto"`
	OrigSrc    string `json:"orig_src"`
	OrigDst    string `json:"orig_dst"`
	OrigSport  uint16 `json:"orig_sport"`
	OrigDport  uint16 `json:"orig_dport"`
	ReplySrc   string `json:"reply_src"` // != OrigDst when DNAT'd
	ReplyDst   string `json:"reply_dst"` // != OrigSrc when SNAT'd
	State      string `json:"state"`     // ESTABLISHED / TIME_WAIT / ASSURED / ...
	NATed      bool   `json:"natted"`
	Packets    uint64 `json:"packets"`
	Bytes      uint64 `json:"bytes"`
	TimeoutSec int    `json:"timeout_sec"`
}

// CTNETLINK message types (NFNL_SUBSYS_CTNETLINK subsystem).
const (
	ipctnlMsgCtGet    = 1
	ipctnlMsgCtDelete = 2
)

// CTA_* top-level conntrack attribute ids. Not exported by x/sys/unix, so
// defined here from linux/netfilter/nfnetlink_conntrack.h.
const (
	ctaTupleOrig     = 1
	ctaTupleReply    = 2
	ctaStatus        = 3
	ctaProtoinfo     = 4
	ctaTimeout       = 7
	ctaCountersOrig  = 9
	ctaCountersReply = 10
)

// Nested tuple / proto / ip / counter / protoinfo attribute ids.
const (
	ctaTupleIP    = 1
	ctaTupleProto = 2

	ctaIPv4Src = 1
	ctaIPv4Dst = 2
	ctaIPv6Src = 3
	ctaIPv6Dst = 4

	ctaProtoNum     = 1
	ctaProtoSrcPort = 2
	ctaProtoDstPort = 3

	ctaCountersPackets = 1
	ctaCountersBytes   = 2

	ctaProtoinfoTCP      = 1
	ctaProtoinfoTCPState = 1
)

// IPS_* status bits (linux/netfilter/nf_conntrack_common.h).
const (
	ipsSeenReply = 0x2
	ipsAssured   = 0x4
	ipsSrcNAT    = 0x8
	ipsDstNAT    = 0x10
)

// tcpStateUnknown is the sentinel returned by parseCtProtoinfoTCP when no TCP
// state attribute is present (e.g. UDP/ICMP flows).
const tcpStateUnknown = 0xff

// ListConntrack dumps the live nf_conntrack table for all families via a
// CTNETLINK IPCTNL_MSG_CT_GET dump. Flows are returned sorted by total bytes
// descending so the heaviest (and the NAT'd) entries surface first; callers
// rendering the table should still cap the row count - it can be enormous on
// a busy router. Returns an empty slice (not an error) when conntrack isn't
// loaded.
func (w *Writer) ListConntrack() ([]ConntrackFlow, error) {
	c, err := netlink.Dial(unix.NETLINK_NETFILTER, nil)
	if err != nil {
		return nil, fmt.Errorf("netlink dial: %w", err)
	}
	defer c.Close()

	resp, err := c.Execute(netlink.Message{
		Header: netlink.Header{
			Type:  netlink.HeaderType(unix.NFNL_SUBSYS_CTNETLINK<<8 | ipctnlMsgCtGet),
			Flags: netlink.Request | netlink.Dump,
		},
		Data: nfgenmsg(unix.AF_UNSPEC),
	})
	if err != nil {
		return nil, fmt.Errorf("ct dump: %w", err)
	}

	out := make([]ConntrackFlow, 0, len(resp))
	for _, m := range resp {
		if len(m.Data) < nfgenmsgLen {
			continue
		}
		f, ok := parseCtAttrs(m.Data[nfgenmsgLen:])
		if !ok {
			continue
		}
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Bytes > out[j].Bytes })
	return out, nil
}

// FlushConntrack deletes one conntrack entry, identified by its original
// tuple. This is the "kill a stuck / translated flow" affordance. Write-gated
// (ErrWritesDisabled when writes are off) and audit-logged, like every other
// netops mutation.
func (w *Writer) FlushConntrack(f ConntrackFlow) error {
	if !w.AllowWrites {
		return ErrWritesDisabled
	}
	proto, ok := protoNumber(f.Proto)
	if !ok {
		return fmt.Errorf("conntrack flush: unsupported proto %q", f.Proto)
	}
	tuple, fam, err := buildCtTuple(f.OrigSrc, f.OrigDst, f.OrigSport, f.OrigDport, proto)
	if err != nil {
		return fmt.Errorf("conntrack flush: %w", err)
	}

	c, err := netlink.Dial(unix.NETLINK_NETFILTER, nil)
	if err != nil {
		return fmt.Errorf("netlink dial: %w", err)
	}
	defer c.Close()

	data := append(nfgenmsg(fam), encodeAttr(ctaTupleOrig|nlaFNested, tuple)...)
	if _, err := c.Execute(netlink.Message{
		Header: netlink.Header{
			Type:  netlink.HeaderType(unix.NFNL_SUBSYS_CTNETLINK<<8 | ipctnlMsgCtDelete),
			Flags: netlink.Request | netlink.Acknowledge,
		},
		Data: data,
	}); err != nil {
		return fmt.Errorf("ct delete: %w", err)
	}
	log.Printf("netops audit: flush conntrack proto=%s orig=%s:%d->%s:%d natted=%v",
		f.Proto, f.OrigSrc, f.OrigSport, f.OrigDst, f.OrigDport, f.NATed)
	return nil
}

// nfgenmsgLen is sizeof(struct nfgenmsg): family(1) version(1) res_id(2).
const nfgenmsgLen = 4

// nfgenmsg builds the 4-byte netfilter generic header that prefixes every
// CTNETLINK message. version is NFNETLINK_V0 (0); res_id is unused here.
func nfgenmsg(family byte) []byte {
	return []byte{family, 0, 0, 0}
}

// ctTuple is the decoded original/reply tuple shared by parseCtAttrs.
type ctTuple struct {
	src, dst     string
	sport, dport uint16
	proto        uint8
	ok           bool
}

// parseCtAttrs decodes the attribute stream of one conntrack message (the
// bytes after the nfgenmsg header) into a ConntrackFlow. Pure over bytes -
// the NAT'd-TCP-flow fixture in the test exercises every nesting level
// without a kernel. ok=false when no original tuple is present.
func parseCtAttrs(b []byte) (ConntrackFlow, bool) {
	var f ConntrackFlow
	var status uint32
	tcpState := uint8(tcpStateUnknown)
	var protoNum uint8
	haveOrig := false

	for _, a := range walkAttrs(b) {
		switch a.Type {
		case ctaTupleOrig:
			if t := parseCtTuple(a.Data); t.ok {
				f.OrigSrc, f.OrigDst = t.src, t.dst
				f.OrigSport, f.OrigDport = t.sport, t.dport
				f.Proto = protoName(t.proto)
				protoNum = t.proto
				haveOrig = true
			}
		case ctaTupleReply:
			if t := parseCtTuple(a.Data); t.ok {
				f.ReplySrc, f.ReplyDst = t.src, t.dst
			}
		case ctaStatus:
			if len(a.Data) >= 4 {
				status = binary.BigEndian.Uint32(a.Data)
			}
		case ctaTimeout:
			if len(a.Data) >= 4 {
				f.TimeoutSec = int(binary.BigEndian.Uint32(a.Data))
			}
		case ctaProtoinfo:
			tcpState = parseCtProtoinfoTCP(a.Data)
		case ctaCountersOrig, ctaCountersReply:
			p, byt := parseCtCounters(a.Data)
			f.Packets += p
			f.Bytes += byt
		}
	}
	if !haveOrig {
		return ConntrackFlow{}, false
	}
	f.NATed = status&(ipsSrcNAT|ipsDstNAT) != 0
	f.State = ctStateName(protoNum, tcpState, status)
	return f, true
}

func parseCtTuple(b []byte) ctTuple {
	var t ctTuple
	for _, a := range walkAttrs(b) {
		switch a.Type {
		case ctaTupleIP:
			t.src, t.dst = parseCtTupleIP(a.Data)
		case ctaTupleProto:
			t.proto, t.sport, t.dport = parseCtTupleProto(a.Data)
		}
	}
	t.ok = t.src != "" || t.dst != ""
	return t
}

func parseCtTupleIP(b []byte) (src, dst string) {
	for _, a := range walkAttrs(b) {
		switch a.Type {
		case ctaIPv4Src, ctaIPv6Src:
			if l := len(a.Data); l == net.IPv4len || l == net.IPv6len {
				src = net.IP(a.Data).String()
			}
		case ctaIPv4Dst, ctaIPv6Dst:
			if l := len(a.Data); l == net.IPv4len || l == net.IPv6len {
				dst = net.IP(a.Data).String()
			}
		}
	}
	return
}

func parseCtTupleProto(b []byte) (proto uint8, sport, dport uint16) {
	for _, a := range walkAttrs(b) {
		switch a.Type {
		case ctaProtoNum:
			if len(a.Data) >= 1 {
				proto = a.Data[0]
			}
		case ctaProtoSrcPort:
			if len(a.Data) >= 2 {
				sport = binary.BigEndian.Uint16(a.Data)
			}
		case ctaProtoDstPort:
			if len(a.Data) >= 2 {
				dport = binary.BigEndian.Uint16(a.Data)
			}
		}
	}
	return
}

func parseCtCounters(b []byte) (pkts, bytes uint64) {
	for _, a := range walkAttrs(b) {
		switch a.Type {
		case ctaCountersPackets:
			if len(a.Data) >= 8 {
				pkts = binary.BigEndian.Uint64(a.Data)
			}
		case ctaCountersBytes:
			if len(a.Data) >= 8 {
				bytes = binary.BigEndian.Uint64(a.Data)
			}
		}
	}
	return
}

func parseCtProtoinfoTCP(b []byte) uint8 {
	for _, a := range walkAttrs(b) {
		if a.Type != ctaProtoinfoTCP {
			continue
		}
		for _, t := range walkAttrs(a.Data) {
			if t.Type == ctaProtoinfoTCPState && len(t.Data) >= 1 {
				return t.Data[0]
			}
		}
	}
	return tcpStateUnknown
}

// buildCtTuple serialises an original tuple (CTA_TUPLE_IP + CTA_TUPLE_PROTO)
// for a flush request, and reports the address family for the nfgenmsg header.
func buildCtTuple(src, dst string, sport, dport uint16, proto uint8) (tuple []byte, family byte, err error) {
	sip, dip := net.ParseIP(src), net.ParseIP(dst)
	if sip == nil || dip == nil {
		return nil, 0, fmt.Errorf("invalid tuple address %q/%q", src, dst)
	}
	var ipAttrs []byte
	if v4s, v4d := sip.To4(), dip.To4(); v4s != nil && v4d != nil {
		family = unix.AF_INET
		ipAttrs = append(ipAttrs, encodeAttr(ctaIPv4Src|nlaFNetByteOrder, v4s)...)
		ipAttrs = append(ipAttrs, encodeAttr(ctaIPv4Dst|nlaFNetByteOrder, v4d)...)
	} else {
		family = unix.AF_INET6
		ipAttrs = append(ipAttrs, encodeAttr(ctaIPv6Src|nlaFNetByteOrder, sip.To16())...)
		ipAttrs = append(ipAttrs, encodeAttr(ctaIPv6Dst|nlaFNetByteOrder, dip.To16())...)
	}

	var port [2]byte
	var protoAttrs []byte
	protoAttrs = append(protoAttrs, encodeAttr(ctaProtoNum, []byte{proto})...)
	binary.BigEndian.PutUint16(port[:], sport)
	protoAttrs = append(protoAttrs, encodeAttr(ctaProtoSrcPort|nlaFNetByteOrder, append([]byte(nil), port[:]...))...)
	binary.BigEndian.PutUint16(port[:], dport)
	protoAttrs = append(protoAttrs, encodeAttr(ctaProtoDstPort|nlaFNetByteOrder, append([]byte(nil), port[:]...))...)

	tuple = append(tuple, encodeAttr(ctaTupleIP|nlaFNested, ipAttrs)...)
	tuple = append(tuple, encodeAttr(ctaTupleProto|nlaFNested, protoAttrs)...)
	return tuple, family, nil
}

// ctStateName derives a flow state. TCP carries an explicit state in
// CTA_PROTOINFO; other protocols don't, so we fall back to the connection's
// status bits (assured > seen-reply > unreplied).
func ctStateName(proto, tcpState uint8, status uint32) string {
	if proto == unix.IPPROTO_TCP && tcpState != tcpStateUnknown {
		return tcpStateName(tcpState)
	}
	switch {
	case status&ipsAssured != 0:
		return "ASSURED"
	case status&ipsSeenReply != 0:
		return "REPLIED"
	default:
		return "UNREPLIED"
	}
}

func tcpStateName(s uint8) string {
	switch s {
	case 0:
		return "NONE"
	case 1:
		return "SYN_SENT"
	case 2:
		return "SYN_RECV"
	case 3:
		return "ESTABLISHED"
	case 4:
		return "FIN_WAIT"
	case 5:
		return "CLOSE_WAIT"
	case 6:
		return "LAST_ACK"
	case 7:
		return "TIME_WAIT"
	case 8:
		return "CLOSE"
	case 9:
		return "LISTEN"
	default:
		return fmt.Sprintf("TCP_%d", s)
	}
}

func protoNumber(name string) (uint8, bool) {
	switch strings.ToLower(name) {
	case "icmp":
		return unix.IPPROTO_ICMP, true
	case "tcp":
		return unix.IPPROTO_TCP, true
	case "udp":
		return unix.IPPROTO_UDP, true
	case "icmpv6":
		return unix.IPPROTO_ICMPV6, true
	case "sctp":
		return unix.IPPROTO_SCTP, true
	case "gre":
		return unix.IPPROTO_GRE, true
	}
	return 0, false
}

// ConntrackUtilisation reports live-entries / nf_conntrack_max as a 0..1
// ratio so the grade and the NAT-exhaustion anomaly share one number. live is
// the count from a dump (or /proc/.../nf_conntrack_count); max is
// nf_conntrack_max. Returns ok=false when max is unknown so the signal stays
// neutral rather than dividing by zero.
func ConntrackUtilisation(live, max uint64) (ratio float64, ok bool) {
	if max == 0 {
		return 0, false
	}
	return float64(live) / float64(max), true
}
