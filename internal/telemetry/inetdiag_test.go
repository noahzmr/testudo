package telemetry

import (
	"encoding/binary"
	"testing"

	"golang.org/x/sys/unix"
)

// buildTCPInfo synthesises a struct tcp_info of the given length with the
// fields Testudo reads set at their kernel offsets. Length lets tests model
// older kernels with a short tcp_info (tail fields absent).
func buildTCPInfo(length int) []byte {
	b := make([]byte, length)
	put := func(off int, v uint32) {
		if off+4 <= len(b) {
			nativeOrder.PutUint32(b[off:off+4], v)
		}
	}
	if len(b) >= 1 {
		b[0] = 1 // tcpi_state = TCP_ESTABLISHED
	}
	put(16, 1448)  // snd_mss
	put(20, 1448)  // rcv_mss
	put(32, 3)     // lost
	put(60, 1500)  // pmtu
	put(68, 25000) // rtt (us) = 25ms
	put(72, 5000)  // rttvar
	put(80, 10)    // snd_cwnd
	put(100, 7)    // total_retrans
	put(136, 1000) // segs_out
	return b
}

// buildInetDiagMsg synthesises an inet_diag_msg (IPv4) with one INET_DIAG_INFO
// attribute carrying the supplied tcp_info bytes.
func buildInetDiagMsg(sport, dport uint16, src, dst [4]byte, tcpInfo []byte) []byte {
	msg := make([]byte, inetDiagMsgLen)
	msg[0] = unix.AF_INET
	msg[1] = 1 // state ESTABLISHED
	binary.BigEndian.PutUint16(msg[sockidOff+0:], sport)
	binary.BigEndian.PutUint16(msg[sockidOff+2:], dport)
	copy(msg[sockidOff+4:], src[:])
	copy(msg[sockidOff+20:], dst[:])

	attrLen := nlaHdrLen + len(tcpInfo)
	attr := make([]byte, (attrLen+3)&^3)
	nativeOrder.PutUint16(attr[0:2], uint16(attrLen))
	nativeOrder.PutUint16(attr[2:4], inetDiagInfo)
	copy(attr[nlaHdrLen:], tcpInfo)

	return append(msg, attr...)
}

func TestParseSample(t *testing.T) {
	raw := buildInetDiagMsg(
		54321, 443,
		[4]byte{192, 168, 1, 20}, [4]byte{1, 1, 1, 1},
		buildTCPInfo(160),
	)
	s, ok := parseSample(raw)
	if !ok {
		t.Fatal("parseSample returned ok=false on a valid message")
	}
	if s.SrcIP != "192.168.1.20" || s.DstIP != "1.1.1.1" {
		t.Errorf("addrs: got %s -> %s", s.SrcIP, s.DstIP)
	}
	if s.SrcPort != 54321 || s.DstPort != 443 {
		t.Errorf("ports: got %d -> %d", s.SrcPort, s.DstPort)
	}
	if s.RTTus != 25000 || s.RTTVarus != 5000 {
		t.Errorf("rtt: got rtt=%d rttvar=%d", s.RTTus, s.RTTVarus)
	}
	if s.Cwnd != 10 {
		t.Errorf("cwnd: got %d, want 10", s.Cwnd)
	}
	if s.TotalRetrans != 7 || s.SegsOut != 1000 {
		t.Errorf("counters: total_retrans=%d segs_out=%d", s.TotalRetrans, s.SegsOut)
	}
	if s.PMTU != 1500 || s.SndMSS != 1448 {
		t.Errorf("pmtu=%d snd_mss=%d", s.PMTU, s.SndMSS)
	}
	if s.Source != SourceInetDiag {
		t.Errorf("source: got %q", s.Source)
	}
}

func TestParseSampleShortTCPInfo(t *testing.T) {
	// An older kernel's tcp_info ends before segs_out (offset 136). The tail
	// fields must read as zero, not panic.
	raw := buildInetDiagMsg(
		1234, 80,
		[4]byte{10, 0, 0, 5}, [4]byte{10, 0, 0, 1},
		buildTCPInfo(104), // stops just after total_retrans
	)
	s, ok := parseSample(raw)
	if !ok {
		t.Fatal("ok=false on short tcp_info")
	}
	if s.RTTus != 25000 || s.TotalRetrans != 7 {
		t.Errorf("present fields wrong: rtt=%d retrans=%d", s.RTTus, s.TotalRetrans)
	}
	if s.SegsOut != 0 {
		t.Errorf("absent segs_out should be 0, got %d", s.SegsOut)
	}
}

func TestParseSampleTruncatedMsg(t *testing.T) {
	if _, ok := parseSample(make([]byte, inetDiagMsgLen-1)); ok {
		t.Error("expected ok=false for a message shorter than inet_diag_msg")
	}
}

func TestParseSampleNoTCPInfo(t *testing.T) {
	// A bare inet_diag_msg with no attributes: tuple parses, tcp_info zeroed.
	msg := make([]byte, inetDiagMsgLen)
	msg[0] = unix.AF_INET
	binary.BigEndian.PutUint16(msg[sockidOff+0:], 22)
	binary.BigEndian.PutUint16(msg[sockidOff+2:], 33333)
	copy(msg[sockidOff+4:], []byte{172, 16, 0, 1})
	copy(msg[sockidOff+20:], []byte{172, 16, 0, 9})
	s, ok := parseSample(msg)
	if !ok {
		t.Fatal("ok=false on attribute-less message")
	}
	if s.SrcPort != 22 || s.RTTus != 0 {
		t.Errorf("got sport=%d rtt=%d", s.SrcPort, s.RTTus)
	}
}

func TestBuildInetDiagReq(t *testing.T) {
	req := buildInetDiagReq(unix.AF_INET6, unix.IPPROTO_TCP)
	if len(req) != inetDiagReqLen {
		t.Fatalf("req length: got %d, want %d", len(req), inetDiagReqLen)
	}
	if req[0] != unix.AF_INET6 {
		t.Errorf("family byte: got %d", req[0])
	}
	if req[1] != unix.IPPROTO_TCP {
		t.Errorf("proto byte: got %d", req[1])
	}
	if req[2] != extInfoBit {
		t.Errorf("idiag_ext: got %#x, want %#x", req[2], extInfoBit)
	}
	states := nativeOrder.Uint32(req[4:8])
	if states&(1<<tcpListen) != 0 {
		t.Error("LISTEN state should be excluded from the dump request")
	}
	if states&(1<<1) == 0 {
		t.Error("ESTABLISHED state should be included in the dump request")
	}
}
