package ipfix

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/noahzmr/testudo/internal/flows"
)

// TestMessageCarriesTranslation decodes what the exporter sends: the
// template announces the post-NAT fields, every record has the template's
// length, and a translated flow carries both sides of the translation.
func TestMessageCarriesTranslation(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	exp, err := NewExporter(Config{Endpoint: pc.LocalAddr().String(), DomainID: 7})
	if err != nil {
		t.Fatal(err)
	}
	defer exp.Close()
	now := time.Now()
	f := flows.FlowStats{Key: flows.FlowKey{Iface: "wan0", Proto: "tcp", A: flows.Endpoint{IP: "192.0.2.1", Port: 8443}, B: flows.Endpoint{IP: "192.0.2.2", Port: 40555}},
		Bytes: 5000, Packets: 9, FirstSeen: now, LastSeen: now,
		Attrs: flows.Attrs{PreNAT: "tcp 192.0.2.2:40555 > 192.0.2.1:8443", PostNAT: "tcp 192.0.2.2:40555 > 10.50.0.2:443"}}
	plain := flows.FlowStats{Key: flows.FlowKey{Proto: "udp", A: flows.Endpoint{IP: "10.0.0.1", Port: 53}, B: flows.Endpoint{IP: "10.0.0.2", Port: 5353}},
		FirstSeen: now, LastSeen: now}
	v6 := flows.FlowStats{Key: flows.FlowKey{Proto: "udp", A: flows.Endpoint{IP: "2001:db8::1", Port: 1}, B: flows.Endpoint{IP: "2001:db8::2", Port: 2}}}
	if err := exp.Export(toFlowRecs([]flows.FlowStats{f, plain, v6})); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 65535)
	pc.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	msg := buf[:n]
	if binary.BigEndian.Uint16(msg[0:2]) != 10 || int(binary.BigEndian.Uint16(msg[2:4])) != n {
		t.Fatalf("header: version %d length %d of %d", binary.BigEndian.Uint16(msg[0:2]), binary.BigEndian.Uint16(msg[2:4]), n)
	}
	recordLen, fields := 0, map[uint16]int{}
	var records [][]byte
	for off := 16; off < n; {
		id, l := binary.BigEndian.Uint16(msg[off:]), int(binary.BigEndian.Uint16(msg[off+2:]))
		body := msg[off+4 : off+l]
		switch id {
		case setIDTemplate:
			count := int(binary.BigEndian.Uint16(body[2:]))
			pos := 0
			for i := 0; i < count; i++ {
				ie, w := binary.BigEndian.Uint16(body[4+i*4:]), int(binary.BigEndian.Uint16(body[6+i*4:]))
				fields[ie] = pos
				pos += w
			}
			recordLen = pos
		case templateID:
			if recordLen == 0 || len(body)%recordLen != 0 {
				t.Fatalf("data set of %d bytes for records of %d", len(body), recordLen)
			}
			for i := 0; i < len(body); i += recordLen {
				records = append(records, body[i:i+recordLen])
			}
		}
		off += l
	}
	if len(records) != 2 {
		t.Fatalf("%d records, want the two IPv4 flows", len(records))
	}
	ip := func(r []byte, ie uint16) string { return net.IP(r[fields[ie] : fields[ie]+4]).String() }
	port := func(r []byte, ie uint16) uint16 { return binary.BigEndian.Uint16(r[fields[ie]:]) }
	r := records[0]
	if ip(r, ieSourceIPv4Address) != "192.0.2.2" || port(r, ieSourceTransportPort) != 40555 || ip(r, ieDestinationIPv4Address) != "192.0.2.1" ||
		ip(r, iePostNATDestinationIPv4Address) != "10.50.0.2" || port(r, iePostNAPTDestinationTransportPort) != 443 ||
		ip(r, iePostNATSourceIPv4Address) != "192.0.2.2" {
		t.Errorf("translated record: %s:%d > %s:%d after %s > %s:%d", ip(r, ieSourceIPv4Address), port(r, ieSourceTransportPort),
			ip(r, ieDestinationIPv4Address), port(r, ieDestinationTransportPort), ip(r, iePostNATSourceIPv4Address),
			ip(r, iePostNATDestinationIPv4Address), port(r, iePostNAPTDestinationTransportPort))
	}
	if r = records[1]; ip(r, iePostNATDestinationIPv4Address) != "10.0.0.2" || port(r, iePostNAPTSourceTransportPort) != 53 {
		t.Errorf("untranslated record: post-NAT should equal pre-NAT")
	}
}
