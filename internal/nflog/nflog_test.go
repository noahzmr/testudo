package nflog

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

// packet builds a NFULNL_MSG_PACKET as the kernel sends it.
func packet(prefix string, in uint32, payload []byte) []byte {
	be32 := func(v uint32) []byte { b := make([]byte, 4); binary.BigEndian.PutUint32(b, v); return b }
	body := []byte{afInet, 0, 0, Group}
	body = append(body, attr(attrPrefix, append([]byte(prefix), 0))...)
	body = append(body, attr(attrInDev, be32(in))...)
	body = append(body, attr(attrPayload, payload)...)
	b := make([]byte, nlmsgHdrLen)
	put32(b, uint32(nlmsgHdrLen+len(body)))
	put16(b[4:], subsysULog<<8|msgPacket)
	return append(b, body...)
}

func TestParseAUDPPacket(t *testing.T) {
	ip := []byte{0x45, 0, 0, 33, 0, 0, 0, 0, 64, protoUDP, 0, 0, 192, 0, 2, 10, 198, 51, 100, 7,
		0x30, 0x39, 0x01, 0xbb, 0, 13, 0, 0, 'h', 'e', 'l', 'l', 'o'}
	msgs := append(packet("t:rule-1", 3, ip), packet("t:drop:input", 4, ip)...)
	evs := Parse(msgs)
	if len(evs) != 2 {
		t.Fatalf("%d entries", len(evs))
	}
	e := evs[0]
	if e.Prefix != "t:rule-1" || e.InDev != 3 || e.Src != netip.MustParseAddr("192.0.2.10") || e.Dst != netip.MustParseAddr("198.51.100.7") ||
		e.ProtoName() != "udp" || e.SrcPort != 12345 || e.DstPort != 443 || e.Length != 33 {
		t.Errorf("entry: %+v", e)
	}
	if evs[1].Prefix != "t:drop:input" {
		t.Errorf("second: %+v", evs[1])
	}
	// A truncated datagram yields what is whole.
	if got := Parse(msgs[:len(msgs)-5]); len(got) != 1 {
		t.Errorf("truncated: %d entries", len(got))
	}
}

func TestBindMessagesAskForTheHeadersOnly(t *testing.T) {
	msgs := bindMessages(Group)
	last := msgs[len(msgs)-1]
	// header, nfgenmsg, then the mode attribute: be32 range, u8 mode.
	mode := last[nlmsgHdrLen+nfgenHdrLen+4:]
	if binary.BigEndian.Uint32(mode) != CopyRange || mode[4] != copyPacket {
		t.Errorf("mode: % x", mode[:6])
	}
	if g := binary.BigEndian.Uint16(last[nlmsgHdrLen+2:]); g != Group {
		t.Errorf("group %d", g)
	}
}
