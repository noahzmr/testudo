package netops

import (
	"encoding/binary"
	"net"
	"testing"
)

// be32/be64 build big-endian payloads, matching how netfilter stores
// addresses, counters and the status word on the wire (be16 lives in nat.go).
func be32(v uint32) []byte { b := make([]byte, 4); binary.BigEndian.PutUint32(b, v); return b }
func be64(v uint64) []byte { b := make([]byte, 8); binary.BigEndian.PutUint64(b, v); return b }

func ctIPv4Tuple(src, dst string) []byte {
	ip := append(encodeAttr(ctaIPv4Src, net.ParseIP(src).To4()), encodeAttr(ctaIPv4Dst, net.ParseIP(dst).To4())...)
	return encodeAttr(ctaTupleIP|nlaFNested, ip)
}

func ctProtoTuple(proto uint8, sport, dport uint16) []byte {
	p := encodeAttr(ctaProtoNum, []byte{proto})
	p = append(p, encodeAttr(ctaProtoSrcPort, be16(sport))...)
	p = append(p, encodeAttr(ctaProtoDstPort, be16(dport))...)
	return encodeAttr(ctaTupleProto|nlaFNested, p)
}

func ctCounters(pkts, bytes uint64) []byte {
	c := append(encodeAttr(ctaCountersPackets, be64(pkts)), encodeAttr(ctaCountersBytes, be64(bytes))...)
	return c
}

// TestParseCtAttrs_NATedTCPFlow exercises every nesting level: an SNAT'd
// ESTABLISHED TCP flow whose reply tuple differs from the original.
func TestParseCtAttrs_NATedTCPFlow(t *testing.T) {
	// Original: LAN client -> remote :443.
	orig := append(ctIPv4Tuple("192.168.1.50", "93.184.216.34"), ctProtoTuple(6, 51000, 443)...)
	// Reply after SNAT: remote -> WAN address (reply dst != orig src).
	reply := append(ctIPv4Tuple("93.184.216.34", "203.0.113.5"), ctProtoTuple(6, 443, 51000)...)

	var msg []byte
	msg = append(msg, encodeAttr(ctaTupleOrig|nlaFNested, orig)...)
	msg = append(msg, encodeAttr(ctaTupleReply|nlaFNested, reply)...)
	msg = append(msg, encodeAttr(ctaStatus, be32(ipsSeenReply|ipsAssured|ipsSrcNAT))...)
	msg = append(msg, encodeAttr(ctaTimeout, be32(432000))...)
	// PROTOINFO -> TCP -> STATE = ESTABLISHED(3).
	tcp := encodeAttr(ctaProtoinfoTCP|nlaFNested, encodeAttr(ctaProtoinfoTCPState, []byte{3}))
	msg = append(msg, encodeAttr(ctaProtoinfo|nlaFNested, tcp)...)
	msg = append(msg, encodeAttr(ctaCountersOrig|nlaFNested, ctCounters(10, 1000))...)
	msg = append(msg, encodeAttr(ctaCountersReply|nlaFNested, ctCounters(8, 800))...)

	f, ok := parseCtAttrs(msg)
	if !ok {
		t.Fatal("parseCtAttrs returned ok=false for a valid NAT'd TCP flow")
	}
	if f.Proto != "tcp" {
		t.Errorf("Proto = %q, want tcp", f.Proto)
	}
	if f.OrigSrc != "192.168.1.50" || f.OrigDst != "93.184.216.34" {
		t.Errorf("orig = %s -> %s, want 192.168.1.50 -> 93.184.216.34", f.OrigSrc, f.OrigDst)
	}
	if f.OrigSport != 51000 || f.OrigDport != 443 {
		t.Errorf("orig ports = %d -> %d, want 51000 -> 443", f.OrigSport, f.OrigDport)
	}
	if f.ReplyDst != "203.0.113.5" {
		t.Errorf("ReplyDst = %q, want 203.0.113.5 (SNAT mapping)", f.ReplyDst)
	}
	if !f.NATed {
		t.Error("NATed = false, want true (IPS_SRC_NAT set)")
	}
	if f.State != "ESTABLISHED" {
		t.Errorf("State = %q, want ESTABLISHED", f.State)
	}
	if f.Packets != 18 || f.Bytes != 1800 {
		t.Errorf("counters = %d pkts / %d bytes, want 18 / 1800", f.Packets, f.Bytes)
	}
	if f.TimeoutSec != 432000 {
		t.Errorf("TimeoutSec = %d, want 432000", f.TimeoutSec)
	}
}

// TestParseCtAttrs_UDPUnreplied: no TCP protoinfo, status drives the state.
func TestParseCtAttrs_UDPUnreplied(t *testing.T) {
	orig := append(ctIPv4Tuple("192.168.1.50", "8.8.8.8"), ctProtoTuple(17, 40000, 53)...)
	var msg []byte
	msg = append(msg, encodeAttr(ctaTupleOrig|nlaFNested, orig)...)
	msg = append(msg, encodeAttr(ctaStatus, be32(0))...) // no SEEN_REPLY

	f, ok := parseCtAttrs(msg)
	if !ok {
		t.Fatal("parseCtAttrs ok=false for a UDP flow")
	}
	if f.Proto != "udp" {
		t.Errorf("Proto = %q, want udp", f.Proto)
	}
	if f.State != "UNREPLIED" {
		t.Errorf("State = %q, want UNREPLIED", f.State)
	}
	if f.NATed {
		t.Error("NATed = true, want false")
	}
}

func TestParseCtAttrs_NoTuple(t *testing.T) {
	if _, ok := parseCtAttrs(encodeAttr(ctaStatus, be32(ipsAssured))); ok {
		t.Error("parseCtAttrs should return ok=false when no original tuple is present")
	}
}

func TestProtoNumberRoundTrip(t *testing.T) {
	for _, name := range []string{"tcp", "udp", "icmp", "icmpv6", "sctp", "gre"} {
		if _, ok := protoNumber(name); !ok {
			t.Errorf("protoNumber(%q) ok=false", name)
		}
	}
	if _, ok := protoNumber("nope"); ok {
		t.Error("protoNumber(nope) should be ok=false")
	}
}

func TestFlushConntrackWriteGated(t *testing.T) {
	w := &Writer{AllowWrites: false}
	err := w.FlushConntrack(ConntrackFlow{Proto: "tcp", OrigSrc: "192.168.1.5", OrigDst: "1.1.1.1", OrigSport: 1234, OrigDport: 443})
	if err != ErrWritesDisabled {
		t.Errorf("FlushConntrack with writes off = %v, want ErrWritesDisabled", err)
	}
}

func TestBuildCtTuple(t *testing.T) {
	tuple, fam, err := buildCtTuple("192.168.1.50", "93.184.216.34", 51000, 443, 6)
	if err != nil {
		t.Fatalf("buildCtTuple: %v", err)
	}
	if fam != 2 { // AF_INET
		t.Errorf("family = %d, want 2 (AF_INET)", fam)
	}
	// Round-trip: the tuple we build must decode back to the same values.
	got := parseCtTuple(tuple)
	if !got.ok || got.src != "192.168.1.50" || got.dst != "93.184.216.34" {
		t.Errorf("round-trip tuple = %+v", got)
	}
	if got.proto != 6 || got.sport != 51000 || got.dport != 443 {
		t.Errorf("round-trip proto/ports = %d/%d/%d", got.proto, got.sport, got.dport)
	}
}

func TestConntrackUtilisation(t *testing.T) {
	if r, ok := ConntrackUtilisation(8000, 16000); !ok || r != 0.5 {
		t.Errorf("util = %f ok=%v, want 0.5 true", r, ok)
	}
	if _, ok := ConntrackUtilisation(10, 0); ok {
		t.Error("util with max=0 should be ok=false")
	}
}
