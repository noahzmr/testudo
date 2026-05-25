package discovery

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"strings"
	"time"
)

// SNMP discovery — hand-rolled SNMPv2c GET over UDP/161. Pulls the five
// most useful sysX.0 OIDs from any device that responds with a configured
// read community. No external dependency; the BER encoder is just enough
// to build a fixed-shape GetRequest PDU and parse the corresponding
// GetResponse.
//
// Why hand-rolled: the rest of discovery (mDNS, LLDP) follows the same
// "small bespoke parser" pattern. SNMPv2c needs ~250 lines of code,
// avoids pulling in another transitive dep, and the OID set is fixed.
//
// Read community defaults to "public" which is the worldwide convention
// for read-only access on managed gear. Operators that want a different
// community (e.g. an audit account) override via Config.SNMPCommunity.

// Well-known sysX.0 OIDs from SNMPv2-MIB. Encoded as integer slices —
// the BER encoder converts them on the wire.
var (
	oidSysDescr    = []int{1, 3, 6, 1, 2, 1, 1, 1, 0}
	oidSysObjectID = []int{1, 3, 6, 1, 2, 1, 1, 2, 0}
	oidSysUptime   = []int{1, 3, 6, 1, 2, 1, 1, 3, 0}
	oidSysContact  = []int{1, 3, 6, 1, 2, 1, 1, 4, 0}
	oidSysName     = []int{1, 3, 6, 1, 2, 1, 1, 5, 0}
	oidSysLocation = []int{1, 3, 6, 1, 2, 1, 1, 6, 0}
	oidIfNumber    = []int{1, 3, 6, 1, 2, 1, 2, 1, 0}
)

// snmpProbeAll runs SNMPGet against every host with UDP/161 open. Bounded
// concurrency keeps the burst small; per-host timeout keeps overall
// wall-clock predictable. Results land in the inventory under Source="snmp".
func (s *Scanner) snmpProbeAll(ctx context.Context, community string, timeout time.Duration) {
	if s == nil || s.Inventory == nil || community == "" {
		return
	}
	if timeout <= 0 {
		timeout = time.Second
	}
	devs := s.Inventory.Snapshot()
	type job struct{ ip string }
	jobs := make(chan job, 8)
	doneCh := make(chan struct{})
	const workers = 16
	for i := 0; i < workers; i++ {
		go func() {
			for j := range jobs {
				if ctx.Err() != nil {
					continue
				}
				if d, err := SNMPGet(ctx, j.ip, community, timeout); err == nil {
					d.IP = j.ip
					d.Source = "snmp"
					if d.Hostname == "" {
						d.Hostname = d.SysName
					}
					if cls := classifyFromSNMP(d); cls != "" {
						d.DeviceType = cls
					}
					s.Inventory.Observe(d)
				}
			}
			doneCh <- struct{}{}
		}()
	}
	for _, d := range devs {
		// Only bother for hosts whose UDP/161 looked open. The earlier
		// UDPProbe records that; a host with no open-port info gets
		// queried optimistically once per slow tick.
		eligible := false
		for _, p := range d.OpenPorts {
			if p == 161 {
				eligible = true
				break
			}
		}
		if !eligible && len(d.OpenPorts) > 0 {
			continue
		}
		jobs <- job{ip: d.IP}
	}
	close(jobs)
	for i := 0; i < workers; i++ {
		<-doneCh
	}
}

// SNMPGet sends a single GetRequest for the well-known sysX.0 + ifNumber.0
// OIDs and decodes the response into a Device. Returns an error when the
// host does not respond or when the SNMP error-status byte is non-zero.
func SNMPGet(ctx context.Context, ip, community string, timeout time.Duration) (Device, error) {
	var d Device
	addr := net.JoinHostPort(ip, "161")
	conn, err := net.DialTimeout("udp", addr, timeout)
	if err != nil {
		return d, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	reqID := int32(rand.Uint32() & 0x7fffffff)
	oids := [][]int{oidSysDescr, oidSysObjectID, oidSysUptime, oidSysContact, oidSysName, oidSysLocation, oidIfNumber}
	pkt, err := buildSNMPv2cGet(community, reqID, oids)
	if err != nil {
		return d, err
	}
	if _, err := conn.Write(pkt); err != nil {
		return d, err
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return d, err
	}
	vbs, err := parseSNMPv2cResponse(buf[:n], reqID)
	if err != nil {
		return d, err
	}
	for _, vb := range vbs {
		key := oidString(vb.oid)
		switch key {
		case oidString(oidSysDescr):
			d.SysDescr = vb.asString()
		case oidString(oidSysObjectID):
			d.SysObjectID = oidStringFromBER(vb.value)
		case oidString(oidSysUptime):
			d.SysUptime = formatTicks(vb.asUint64())
		case oidString(oidSysContact):
			d.SysContact = vb.asString()
		case oidString(oidSysName):
			d.SysName = vb.asString()
		case oidString(oidSysLocation):
			d.SysLocation = vb.asString()
		case oidString(oidIfNumber):
			d.IfCount = int(vb.asUint64())
		}
	}
	if d.SysName == "" && d.SysDescr == "" {
		return d, errors.New("snmp: empty response")
	}
	return d, nil
}

// classifyFromSNMP infers a coarse DeviceType from sysDescr and the
// interface count. Cheap heuristics, never authoritative — meant to give
// the UI a column to colourise. Real classification would key off
// sysObjectID against a vendor MIB index.
func classifyFromSNMP(d Device) string {
	desc := strings.ToLower(d.SysDescr)
	switch {
	case strings.Contains(desc, "router"), strings.Contains(desc, "mikrotik"), strings.Contains(desc, "ios"):
		return "router"
	case strings.Contains(desc, "switch"), strings.Contains(desc, "catalyst"), strings.Contains(desc, "procurve"):
		return "switch"
	case strings.Contains(desc, "access point"), strings.Contains(desc, "aironet"), strings.Contains(desc, "unifi"):
		return "ap"
	case strings.Contains(desc, "printer"), strings.Contains(desc, "jetdirect"):
		return "printer"
	case strings.Contains(desc, "linux"), strings.Contains(desc, "ubuntu"), strings.Contains(desc, "debian"):
		if d.IfCount > 4 {
			return "server"
		}
		return "workstation"
	case strings.Contains(desc, "windows"):
		return "workstation"
	case strings.Contains(desc, "esxi"), strings.Contains(desc, "vmware"):
		return "hypervisor"
	}
	return ""
}

// --- BER encoder / decoder (just enough for SNMPv2c GET) ---------------

// SNMP types we encode/decode. Standard ASN.1 universals plus SNMP
// application tags (Counter32, Gauge32, TimeTicks, Counter64, IpAddress).
const (
	asnInteger     = 0x02
	asnOctetString = 0x04
	asnNull        = 0x05
	asnOID         = 0x06
	asnSequence    = 0x30
	asnIpAddress   = 0x40
	asnCounter32   = 0x41
	asnGauge32     = 0x42
	asnTimeTicks   = 0x43
	asnCounter64   = 0x46
	asnGetRequest  = 0xa0
	asnGetResponse = 0xa2
)

// varbind is one (OID, value) pair from a GetResponse. value retains the
// raw ASN.1 type + bytes so callers pick the right accessor.
type varbind struct {
	oid   []int
	typ   byte
	value []byte
}

func (v varbind) asString() string {
	switch v.typ {
	case asnOctetString:
		return strings.TrimRight(string(v.value), "\x00")
	}
	return ""
}

func (v varbind) asUint64() uint64 {
	if len(v.value) == 0 || len(v.value) > 8 {
		return 0
	}
	var x uint64
	for _, b := range v.value {
		x = (x << 8) | uint64(b)
	}
	return x
}

// buildSNMPv2cGet encodes an SNMPv2c GetRequest carrying the given OIDs,
// each paired with an ASN.1 Null value (SNMP convention for "give me
// this OID's current value"). Returns the wire-format datagram.
func buildSNMPv2cGet(community string, reqID int32, oids [][]int) ([]byte, error) {
	var vbs []byte
	for _, oid := range oids {
		o, err := encodeOID(oid)
		if err != nil {
			return nil, err
		}
		oidTLV := append([]byte{asnOID}, encodeLength(len(o))...)
		oidTLV = append(oidTLV, o...)
		nullTLV := []byte{asnNull, 0x00}
		inner := append(oidTLV, nullTLV...)
		vb := append([]byte{asnSequence}, encodeLength(len(inner))...)
		vb = append(vb, inner...)
		vbs = append(vbs, vb...)
	}
	vbList := append([]byte{asnSequence}, encodeLength(len(vbs))...)
	vbList = append(vbList, vbs...)

	pdu := encodeInteger(int64(reqID)) // request-id
	pdu = append(pdu, encodeInteger(0)...) // error-status
	pdu = append(pdu, encodeInteger(0)...) // error-index
	pdu = append(pdu, vbList...)
	pduWrapped := append([]byte{asnGetRequest}, encodeLength(len(pdu))...)
	pduWrapped = append(pduWrapped, pdu...)

	msg := encodeInteger(1) // version: SNMPv2c (0=v1, 1=v2c)
	msg = append(msg, asnOctetString)
	msg = append(msg, encodeLength(len(community))...)
	msg = append(msg, []byte(community)...)
	msg = append(msg, pduWrapped...)

	out := append([]byte{asnSequence}, encodeLength(len(msg))...)
	out = append(out, msg...)
	return out, nil
}

// parseSNMPv2cResponse pulls the varbind list out of a GetResponse PDU and
// verifies the request-id matches our request. Errors are returned for
// malformed packets and for non-zero SNMP error-status.
func parseSNMPv2cResponse(p []byte, wantReqID int32) ([]varbind, error) {
	r, err := readTLV(p)
	if err != nil || r.tag != asnSequence {
		return nil, errors.New("snmp: bad outer sequence")
	}
	// version
	v, err := readTLV(r.value)
	if err != nil || v.tag != asnInteger {
		return nil, errors.New("snmp: bad version")
	}
	rest := r.value[v.consumed:]
	// community
	c, err := readTLV(rest)
	if err != nil || c.tag != asnOctetString {
		return nil, errors.New("snmp: bad community")
	}
	rest = rest[c.consumed:]
	// PDU
	pdu, err := readTLV(rest)
	if err != nil {
		return nil, err
	}
	if pdu.tag != asnGetResponse {
		return nil, fmt.Errorf("snmp: pdu type %02x", pdu.tag)
	}
	body := pdu.value
	rid, err := readTLV(body)
	if err != nil || rid.tag != asnInteger {
		return nil, errors.New("snmp: bad request-id")
	}
	if decodeInteger(rid.value) != int64(wantReqID) {
		return nil, errors.New("snmp: request-id mismatch")
	}
	body = body[rid.consumed:]
	es, err := readTLV(body)
	if err != nil {
		return nil, err
	}
	if decodeInteger(es.value) != 0 {
		return nil, fmt.Errorf("snmp: error-status %d", decodeInteger(es.value))
	}
	body = body[es.consumed:]
	ei, err := readTLV(body)
	if err != nil {
		return nil, err
	}
	body = body[ei.consumed:]
	vbList, err := readTLV(body)
	if err != nil || vbList.tag != asnSequence {
		return nil, errors.New("snmp: bad varbind list")
	}
	return parseVarbinds(vbList.value), nil
}

func parseVarbinds(p []byte) []varbind {
	var out []varbind
	for len(p) > 0 {
		vb, err := readTLV(p)
		if err != nil || vb.tag != asnSequence {
			return out
		}
		oidT, err := readTLV(vb.value)
		if err != nil || oidT.tag != asnOID {
			return out
		}
		valT, err := readTLV(vb.value[oidT.consumed:])
		if err != nil {
			return out
		}
		out = append(out, varbind{
			oid:   decodeOID(oidT.value),
			typ:   valT.tag,
			value: valT.value,
		})
		p = p[vb.consumed:]
	}
	return out
}

// tlv is a parsed Type-Length-Value record from the BER stream. consumed
// is the total wire length (tag + length-bytes + value), so callers can
// stride past it.
type tlv struct {
	tag      byte
	value    []byte
	consumed int
}

func readTLV(p []byte) (tlv, error) {
	if len(p) < 2 {
		return tlv{}, errors.New("snmp: truncated TLV")
	}
	tag := p[0]
	length, lenBytes, err := decodeLength(p[1:])
	if err != nil {
		return tlv{}, err
	}
	start := 1 + lenBytes
	if start+length > len(p) {
		return tlv{}, errors.New("snmp: TLV exceeds buffer")
	}
	return tlv{
		tag:      tag,
		value:    p[start : start+length],
		consumed: start + length,
	}, nil
}

// encodeLength writes BER definite-length: short form for <128, long form
// otherwise (0x80 | numBytes, then big-endian length bytes).
func encodeLength(n int) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	}
	var buf [8]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte(n & 0xff)
		n >>= 8
	}
	nb := len(buf) - i
	return append([]byte{0x80 | byte(nb)}, buf[i:]...)
}

func decodeLength(p []byte) (int, int, error) {
	if len(p) == 0 {
		return 0, 0, errors.New("snmp: empty length")
	}
	b := p[0]
	if b < 0x80 {
		return int(b), 1, nil
	}
	nb := int(b & 0x7f)
	if nb == 0 || nb > len(p)-1 {
		return 0, 0, errors.New("snmp: bad long-form length")
	}
	v := 0
	for i := 0; i < nb; i++ {
		v = (v << 8) | int(p[1+i])
	}
	return v, 1 + nb, nil
}

// encodeInteger writes a minimal two's-complement BER INTEGER.
func encodeInteger(v int64) []byte {
	if v == 0 {
		return []byte{asnInteger, 0x01, 0x00}
	}
	var buf [9]byte
	i := len(buf)
	for {
		i--
		buf[i] = byte(v & 0xff)
		v >>= 8
		if v == 0 || v == -1 {
			break
		}
	}
	// Ensure sign extension is correct.
	if buf[i]&0x80 != 0 && v == 0 {
		i--
		buf[i] = 0
	} else if buf[i]&0x80 == 0 && v == -1 {
		i--
		buf[i] = 0xff
	}
	body := buf[i:]
	return append([]byte{asnInteger}, append(encodeLength(len(body)), body...)...)
}

func decodeInteger(p []byte) int64 {
	if len(p) == 0 {
		return 0
	}
	var v int64
	if p[0]&0x80 != 0 {
		v = -1
	}
	for _, b := range p {
		v = (v << 8) | int64(b)
	}
	return v
}

// encodeOID encodes a numeric OID into BER. First two sub-identifiers are
// packed as 40*a + b; subsequent ones use base-128 with the high bit set
// on all but the last byte.
func encodeOID(oid []int) ([]byte, error) {
	if len(oid) < 2 {
		return nil, errors.New("snmp: OID too short")
	}
	out := []byte{byte(40*oid[0] + oid[1])}
	for _, sub := range oid[2:] {
		out = append(out, base128(uint32(sub))...)
	}
	return out, nil
}

func decodeOID(p []byte) []int {
	if len(p) == 0 {
		return nil
	}
	out := []int{int(p[0]) / 40, int(p[0]) % 40}
	v := uint32(0)
	for _, b := range p[1:] {
		v = (v << 7) | uint32(b&0x7f)
		if b&0x80 == 0 {
			out = append(out, int(v))
			v = 0
		}
	}
	return out
}

func base128(v uint32) []byte {
	if v < 0x80 {
		return []byte{byte(v)}
	}
	var buf [5]byte
	i := len(buf)
	i--
	buf[i] = byte(v & 0x7f)
	v >>= 7
	for v > 0 {
		i--
		buf[i] = byte(v&0x7f) | 0x80
		v >>= 7
	}
	return buf[i:]
}

// oidString prints an OID as a "1.3.6.1.2.1.1.5.0" dotted-decimal string.
// Used as a map key when matching responses back to the request OIDs.
func oidString(oid []int) string {
	b := strings.Builder{}
	for i, v := range oid {
		if i > 0 {
			b.WriteByte('.')
		}
		b.WriteString(fmt.Sprintf("%d", v))
	}
	return b.String()
}

// oidStringFromBER decodes a BER OID value and renders it as a dotted-
// decimal string. Used for sysObjectID which is itself an OID value.
func oidStringFromBER(p []byte) string {
	return oidString(decodeOID(p))
}

// formatTicks renders a TimeTicks value (hundredths of a second since
// agent boot) as a duration string like "12d 4h 3m". A close-enough
// approximation — SNMP TimeTicks wrap every ~497 days.
func formatTicks(ticks uint64) string {
	secs := ticks / 100
	d := secs / 86400
	h := (secs % 86400) / 3600
	m := (secs % 3600) / 60
	if d > 0 {
		return fmt.Sprintf("%dd %dh %dm", d, h, m)
	}
	if h > 0 {
		return fmt.Sprintf("%dh %dm", h, m)
	}
	return fmt.Sprintf("%ds", secs)
}

// Silence the unused-import linter when binary is only consumed via
// imports we may add later. Keeping the symbol live makes future edits
// (e.g. parsing IpAddress / Counter32 explicitly) low-friction.
var _ = binary.BigEndian
