// Package nflog reads the packets that nftables rules log to a netfilter
// log group ("log group N"), over the kernel's nfnetlink_log interface.
//
// Opening and binding the socket needs CAP_NET_ADMIN; reading from it does
// not. The privileged helper therefore opens it and hands the descriptor
// to the engine, which reads. Only the first bytes of each packet are
// copied: enough for the addresses and ports, never the payload.
package nflog

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"time"
)

// Group is the log group Testudo's rules log to.
const Group = 7

// CopyRange is how many bytes of each packet the kernel copies: the IP and
// transport headers.
const CopyRange = 96

// Netlink and nfnetlink_log constants (linux/netfilter/nfnetlink_log.h).
const (
	netlinkNetfilter = 12
	subsysULog       = 4
	msgPacket        = 0
	msgConfig        = 1

	cfgCmd  = 1
	cfgMode = 2

	cmdBind    = 1
	cmdPFBind  = 3
	cmdPFUnbnd = 4
	copyPacket = 2

	attrPacketHdr = 1
	attrTimestamp = 3
	attrInDev     = 4
	attrOutDev    = 5
	attrPayload   = 9
	attrPrefix    = 10

	nlmsgHdrLen = 16
	nfgenHdrLen = 4
	nlmsgError  = 2
	nlmFRequest = 0x1
	nlmFAck     = 0x4
	afInet      = 2
	afInet6     = 10
	protoTCP    = 6
	protoUDP    = 17
	protoICMP   = 1
	protoICMPv6 = 58
	protoSCTP   = 132
)

// Entry is one logged packet.
type Entry struct {
	Time    time.Time  `json:"time"`
	Prefix  string     `json:"prefix"`
	InDev   uint32     `json:"in_dev,omitempty"`  // ifindex
	OutDev  uint32     `json:"out_dev,omitempty"` // ifindex
	Src     netip.Addr `json:"src"`
	Dst     netip.Addr `json:"dst"`
	Proto   uint8      `json:"proto"`
	SrcPort uint16     `json:"src_port,omitempty"`
	DstPort uint16     `json:"dst_port,omitempty"`
	// ICMPType is set for ICMP and ICMPv6.
	ICMPType uint8 `json:"icmp_type,omitempty"`
	Length   int   `json:"length"`
}

// ProtoName names the transport protocol.
func (e Entry) ProtoName() string {
	switch e.Proto {
	case protoTCP:
		return "tcp"
	case protoUDP:
		return "udp"
	case protoICMP:
		return "icmp"
	case protoICMPv6:
		return "icmpv6"
	case protoSCTP:
		return "sctp"
	}
	return fmt.Sprint(e.Proto)
}

func put16(b []byte, v uint16) { binary.NativeEndian.PutUint16(b, v) }
func put32(b []byte, v uint32) { binary.NativeEndian.PutUint32(b, v) }

// attr encodes a netlink attribute, padded to four bytes.
func attr(typ uint16, data []byte) []byte {
	n := 4 + len(data)
	b := make([]byte, (n+3)&^3)
	put16(b, uint16(n))
	put16(b[2:], typ)
	copy(b[4:], data)
	return b
}

// configMsg is one NFULNL_MSG_CONFIG request.
func configMsg(seq uint32, family uint8, group uint16, attrs ...[]byte) []byte {
	body := []byte{family, 0, 0, 0}
	binary.BigEndian.PutUint16(body[2:], group)
	for _, a := range attrs {
		body = append(body, a...)
	}
	b := make([]byte, nlmsgHdrLen, nlmsgHdrLen+len(body))
	put32(b, uint32(nlmsgHdrLen+len(body)))
	put16(b[4:], subsysULog<<8|msgConfig)
	put16(b[6:], nlmFRequest|nlmFAck)
	put32(b[8:], seq)
	return append(b, body...)
}

// bindMessages are the requests that make a socket receive group.
func bindMessages(group uint16) [][]byte {
	modeData := make([]byte, 6)
	binary.BigEndian.PutUint32(modeData, CopyRange)
	modeData[4] = copyPacket
	var out [][]byte
	seq := uint32(1)
	// Older kernels want the families bound; newer ones ignore this.
	for _, fam := range []uint8{afInet, afInet6} {
		out = append(out, configMsg(seq, fam, 0, attr(cfgCmd, []byte{cmdPFUnbnd})))
		seq++
		out = append(out, configMsg(seq, fam, 0, attr(cfgCmd, []byte{cmdPFBind})))
		seq++
	}
	out = append(out, configMsg(seq, 0, group, attr(cfgCmd, []byte{cmdBind})))
	seq++
	out = append(out, configMsg(seq, 0, group, attr(cfgMode, modeData)))
	return out
}

// ackError returns the error a netlink acknowledgement carries, if any.
func ackError(b []byte) error {
	if len(b) < nlmsgHdrLen+4 {
		return errors.New("nflog: short acknowledgement")
	}
	if binary.NativeEndian.Uint16(b[4:]) != nlmsgError {
		return nil
	}
	if code := int32(binary.NativeEndian.Uint32(b[nlmsgHdrLen:])); code != 0 {
		return fmt.Errorf("nflog: kernel refused the configuration: errno %d", -code)
	}
	return nil
}

// Parse decodes every packet message in a netlink datagram.
func Parse(b []byte) []Entry {
	var out []Entry
	for len(b) >= nlmsgHdrLen {
		n := int(binary.NativeEndian.Uint32(b))
		if n < nlmsgHdrLen || n > len(b) {
			break
		}
		typ := binary.NativeEndian.Uint16(b[4:])
		if typ == subsysULog<<8|msgPacket && n >= nlmsgHdrLen+nfgenHdrLen {
			if e, ok := parsePacket(b[nlmsgHdrLen+nfgenHdrLen : n]); ok {
				out = append(out, e)
			}
		}
		b = b[(n+3)&^3:]
	}
	return out
}

func parsePacket(b []byte) (Entry, bool) {
	var e Entry
	var payload []byte
	for len(b) >= 4 {
		n := int(binary.NativeEndian.Uint16(b))
		typ := binary.NativeEndian.Uint16(b[2:]) & 0x3fff
		if n < 4 || n > len(b) {
			break
		}
		v := b[4:n]
		switch typ {
		case attrPrefix:
			for i, c := range v {
				if c == 0 {
					v = v[:i]
					break
				}
			}
			e.Prefix = string(v)
		case attrInDev:
			if len(v) >= 4 {
				e.InDev = binary.BigEndian.Uint32(v)
			}
		case attrOutDev:
			if len(v) >= 4 {
				e.OutDev = binary.BigEndian.Uint32(v)
			}
		case attrTimestamp:
			if len(v) >= 16 {
				e.Time = time.Unix(int64(binary.BigEndian.Uint64(v)), int64(binary.BigEndian.Uint64(v[8:]))*1000)
			}
		case attrPayload:
			payload = v
		}
		b = b[(n+3)&^3:]
	}
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	if len(payload) == 0 {
		return e, e.Prefix != ""
	}
	return e, decodeIP(&e, payload)
}

// decodeIP fills addresses, protocol and ports from the copied headers.
func decodeIP(e *Entry, p []byte) bool {
	var l4 []byte
	switch p[0] >> 4 {
	case 4:
		if len(p) < 20 {
			return false
		}
		ihl := int(p[0]&0x0f) * 4
		e.Length = int(binary.BigEndian.Uint16(p[2:]))
		e.Proto = p[9]
		e.Src = netip.AddrFrom4([4]byte(p[12:16]))
		e.Dst = netip.AddrFrom4([4]byte(p[16:20]))
		if ihl >= 20 && ihl <= len(p) {
			l4 = p[ihl:]
		}
	case 6:
		if len(p) < 40 {
			return false
		}
		e.Length = int(binary.BigEndian.Uint16(p[4:])) + 40
		e.Proto = p[6]
		e.Src = netip.AddrFrom16([16]byte(p[8:24]))
		e.Dst = netip.AddrFrom16([16]byte(p[24:40]))
		l4 = p[40:]
	default:
		return false
	}
	switch e.Proto {
	case protoTCP, protoUDP, protoSCTP:
		if len(l4) >= 4 {
			e.SrcPort = binary.BigEndian.Uint16(l4)
			e.DstPort = binary.BigEndian.Uint16(l4[2:])
		}
	case protoICMP, protoICMPv6:
		if len(l4) >= 1 {
			e.ICMPType = l4[0]
		}
	}
	return true
}
