package telemetry

import (
	"encoding/binary"
	"fmt"
	"net"
	"unsafe"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// nativeOrder is the host byte order. tcp_info fields and the INET_DIAG request
// states bitmap are host-endian; the sockid ports and addresses inside
// inet_diag_msg are big-endian and decoded explicitly below.
var nativeOrder = func() binary.ByteOrder {
	var x uint16 = 1
	if *(*byte)(unsafe.Pointer(&x)) == 1 {
		return binary.LittleEndian
	}
	return binary.BigEndian
}()

// sock_diag wire constants (linux/inet_diag.h, linux/sock_diag.h).
const (
	sockDiagByFamily = 20 // SOCK_DIAG_BY_FAMILY message type

	inetDiagInfo = 2                       // INET_DIAG_INFO attribute (carries struct tcp_info)
	extInfoBit   = 1 << (inetDiagInfo - 1) // idiag_ext request bit for INET_DIAG_INFO

	inetDiagReqLen = 56 // sizeof(struct inet_diag_req_v2)
	inetDiagMsgLen = 72 // sizeof(struct inet_diag_msg)
	sockidOff      = 4  // offset of inet_diag_sockid within inet_diag_msg
	rqueueOff      = 56 // offset of idiag_rqueue (after sockid + idiag_expires)
	wqueueOff      = 60 // offset of idiag_wqueue

	// tcpEstablished is TCP_ESTABLISHED; tcpListen is TCP_LISTEN. The dump
	// requests every state except LISTEN so connected and transitioning
	// sockets are returned but listeners don't flood the result.
	tcpListen = 10

	nlaHdrLen   = 4
	nlaTypeMask = 0x3fff
)

// Sample is one connected TCP socket as reported by INET_DIAG, with the
// tcp_info fields we care about already extracted. The (Src,Dst) tuple is
// directional (local socket first); the flow aggregator canonicalises it.
type Sample struct {
	SrcIP, DstIP     string
	SrcPort, DstPort uint16
	State            uint8

	// RQueue/WQueue are the kernel's receive/send queue depths (bytes) for this
	// socket, carried in inet_diag_msg itself. A send queue that stays non-empty
	// while no new data goes out is the zero-window / send-stall shape.
	RQueue uint32
	WQueue uint32

	RTTus    uint32
	RTTVarus uint32
	Cwnd     uint32
	SndMSS   uint32
	RcvMSS   uint32
	PMTU     uint32
	Lost     uint32

	TotalRetrans uint32 // cumulative; for per-interval RTX-rate derivation
	SegsOut      uint32 // cumulative; the denominator for RTX rate

	Source string // SourceInetDiag
}

// Query dumps connected TCP sockets for both address families via INET_DIAG and
// returns a Sample per socket with tcp_info extracted. Pure Go, no cgo, no
// exec. A dump failure for one family is not fatal as long as the other
// succeeds (IPv6 may be disabled); only a total failure returns an error.
func Query() ([]Sample, error) {
	var out []Sample
	var firstErr error
	for _, fam := range []uint8{unix.AF_INET, unix.AF_INET6} {
		s, err := queryFamily(fam)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		out = append(out, s...)
	}
	if out == nil && firstErr != nil {
		return nil, firstErr
	}
	return out, nil
}

func queryFamily(family uint8) ([]Sample, error) {
	c, err := netlink.Dial(unix.NETLINK_SOCK_DIAG, nil)
	if err != nil {
		return nil, fmt.Errorf("sock_diag dial: %w", err)
	}
	defer c.Close()

	resp, err := c.Execute(netlink.Message{
		Header: netlink.Header{
			Type:  netlink.HeaderType(sockDiagByFamily),
			Flags: netlink.Request | netlink.Dump,
		},
		Data: buildInetDiagReq(family, unix.IPPROTO_TCP),
	})
	if err != nil {
		return nil, fmt.Errorf("inet_diag dump: %w", err)
	}

	out := make([]Sample, 0, len(resp))
	for _, m := range resp {
		s, ok := parseSample(m.Data)
		if !ok {
			continue
		}
		out = append(out, s)
	}
	return out, nil
}

// buildInetDiagReq serialises struct inet_diag_req_v2 requesting TCP sockets in
// every state except LISTEN, with the INET_DIAG_INFO extension so the kernel
// attaches struct tcp_info to each reply.
func buildInetDiagReq(family, proto uint8) []byte {
	b := make([]byte, inetDiagReqLen)
	b[0] = family     // sdiag_family
	b[1] = proto      // sdiag_protocol
	b[2] = extInfoBit // idiag_ext
	b[3] = 0          // pad
	states := uint32(0xffffffff) &^ (1 << tcpListen)
	nativeOrder.PutUint32(b[4:8], states) // idiag_states
	// id (struct inet_diag_sockid, 48 bytes) is left zeroed for a dump.
	return b
}

// parseSample decodes one inet_diag_msg (header + attribute stream) into a
// Sample, extracting tcp_info from the INET_DIAG_INFO attribute. Pure over
// bytes - the parser tests feed it synthesised fixtures, no kernel required.
func parseSample(b []byte) (Sample, bool) {
	if len(b) < inetDiagMsgLen {
		return Sample{}, false
	}
	family := b[0]
	s := Sample{State: b[1], Source: SourceInetDiag}

	sid := b[sockidOff:]
	s.SrcPort = binary.BigEndian.Uint16(sid[0:2])
	s.DstPort = binary.BigEndian.Uint16(sid[2:4])
	srcRaw, dstRaw := sid[4:20], sid[20:36]
	if family == unix.AF_INET {
		s.SrcIP = net.IP(srcRaw[:4]).String()
		s.DstIP = net.IP(dstRaw[:4]).String()
	} else {
		s.SrcIP = net.IP(srcRaw[:16]).String()
		s.DstIP = net.IP(dstRaw[:16]).String()
	}

	// idiag_rqueue / idiag_wqueue live in the fixed message body (host-endian),
	// guaranteed present since len(b) >= inetDiagMsgLen was checked above.
	s.RQueue = nativeOrder.Uint32(b[rqueueOff : rqueueOff+4])
	s.WQueue = nativeOrder.Uint32(b[wqueueOff : wqueueOff+4])

	for _, a := range walkAttrs(b[inetDiagMsgLen:]) {
		if a.Type == inetDiagInfo {
			applyTCPInfo(&s, a.Data)
		}
	}
	return s, true
}

// applyTCPInfo reads the subset of struct tcp_info Testudo uses, at the kernel's
// fixed field offsets. Every read is length-guarded so a short tcp_info from an
// older kernel yields zeros for the absent tail fields rather than panicking.
func applyTCPInfo(s *Sample, b []byte) {
	rd32 := func(off int) (uint32, bool) {
		if off+4 > len(b) {
			return 0, false
		}
		return nativeOrder.Uint32(b[off : off+4]), true
	}
	if v, ok := rd32(16); ok {
		s.SndMSS = v
	}
	if v, ok := rd32(20); ok {
		s.RcvMSS = v
	}
	if v, ok := rd32(32); ok {
		s.Lost = v
	}
	if v, ok := rd32(60); ok {
		s.PMTU = v
	}
	if v, ok := rd32(68); ok {
		s.RTTus = v
	}
	if v, ok := rd32(72); ok {
		s.RTTVarus = v
	}
	if v, ok := rd32(80); ok {
		s.Cwnd = v
	}
	if v, ok := rd32(100); ok {
		s.TotalRetrans = v
	}
	if v, ok := rd32(136); ok {
		s.SegsOut = v
	}
}

// nlAttr is one decoded netlink attribute.
type nlAttr struct {
	Type uint16
	Data []byte
}

// walkAttrs splits an rtattr stream into attributes. Pure over bytes; trailing
// padding/truncation is ignored the way the kernel pads the final attribute.
func walkAttrs(b []byte) []nlAttr {
	var out []nlAttr
	for len(b) >= nlaHdrLen {
		length := int(nativeOrder.Uint16(b[0:2]))
		typ := nativeOrder.Uint16(b[2:4]) & nlaTypeMask
		if length < nlaHdrLen || length > len(b) {
			break
		}
		out = append(out, nlAttr{Type: typ, Data: b[nlaHdrLen:length]})
		adv := (length + 3) &^ 3
		if adv >= len(b) {
			break
		}
		b = b[adv:]
	}
	return out
}
