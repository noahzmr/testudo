package netops

import (
	"encoding/binary"
	"unsafe"
)

// nlnative is the host byte order the kernel uses for netlink message and
// attribute *headers* (nlmsghdr / nlattr lengths and types). Attribute
// payloads may use a different order - netfilter stores addresses, ports and
// counters big-endian regardless of host - so those are decoded explicitly
// where they're read, not through nlnative.
var nlnative = func() binary.ByteOrder {
	var x uint16 = 1
	if *(*byte)(unsafe.Pointer(&x)) == 1 {
		return binary.LittleEndian
	}
	return binary.BigEndian
}()

const (
	// nlaHdrLen is sizeof(struct nlattr): u16 len + u16 type.
	nlaHdrLen = 4
	// nlaTypeMask strips the NLA_F_NESTED / NLA_F_NET_BYTEORDER flag bits
	// from an attribute type, leaving the real attribute id.
	nlaTypeMask = 0x3fff
	// nlaFNested marks an attribute whose payload is a nested attribute
	// stream; nlaFNetByteOrder marks a payload in network byte order. We
	// set them when building requests; the kernel ignores them on input but
	// iproute2/conntrack-tools set them so we mirror that.
	nlaFNested       = 0x8000
	nlaFNetByteOrder = 0x4000
)

// nlAttr is one decoded netlink attribute: its id (flag bits stripped) and
// its raw payload bytes (a sub-slice of the input, not copied).
type nlAttr struct {
	Type uint16
	Data []byte
}

// nlaAlign rounds n up to the 4-byte netlink attribute alignment (NLA_ALIGNTO).
func nlaAlign(n int) int { return (n + 3) &^ 3 }

// walkAttrs splits a netlink attribute stream into its constituent
// attributes. It is a pure function over bytes - no kernel required - which
// is what lets the neighbour and conntrack parsers built on top of it be
// unit-tested against captured fixtures. Malformed or truncated trailing
// bytes are ignored rather than treated as an error, matching how the kernel
// pads the final attribute.
func walkAttrs(b []byte) []nlAttr {
	var out []nlAttr
	for len(b) >= nlaHdrLen {
		length := int(nlnative.Uint16(b[0:2]))
		typ := nlnative.Uint16(b[2:4]) & nlaTypeMask
		if length < nlaHdrLen || length > len(b) {
			break
		}
		out = append(out, nlAttr{Type: typ, Data: b[nlaHdrLen:length]})
		adv := nlaAlign(length)
		if adv >= len(b) {
			break
		}
		b = b[adv:]
	}
	return out
}

// encodeAttr serialises one attribute (header + padded payload) for an
// outgoing netlink request. typ may carry the nlaFNested / nlaFNetByteOrder
// flag bits.
func encodeAttr(typ uint16, data []byte) []byte {
	length := nlaHdrLen + len(data)
	b := make([]byte, nlaAlign(length))
	nlnative.PutUint16(b[0:2], uint16(length))
	nlnative.PutUint16(b[2:4], typ)
	copy(b[nlaHdrLen:], data)
	return b
}
