// Package ipfix exports Testudo flow data over the IETF IPFIX protocol
// (RFC 7011). Wire format is hand-rolled over net.Conn — no external
// dependency. The exporter speaks UDP by default; the manager hooks it
// up to the engine and the Settings tab so operators can point the feed
// at any IPFIX-aware collector (Opsanio, ipfixcol2, nProbe, Elastic
// Network Flow integration, …) with a single endpoint and an interval.
package ipfix

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/fnv"
	"net"
	"os"
	"strings"
	"time"
)

// Wire constants ------------------------------------------------------

const (
	versionIPFIX uint16 = 0x000A

	// Reserved set IDs — anything ≥ 256 is a data-set ID matched against
	// a template the exporter previously announced.
	setIDTemplate uint16 = 2

	// Our private template ID. Picked at the bottom of the user range so
	// it doesn't collide with anything well-known.
	templateID uint16 = 256

	// IANA Information Element IDs we ship in the template. Field widths
	// are documented in https://www.iana.org/assignments/ipfix/ipfix.xhtml
	ieProtocolIdentifier        uint16 = 4
	ieSourceTransportPort       uint16 = 7
	ieSourceIPv4Address         uint16 = 8
	ieDestinationTransportPort  uint16 = 11
	ieDestinationIPv4Address    uint16 = 12
	ieOctetDeltaCount           uint16 = 1
	iePacketDeltaCount          uint16 = 2
	ieFlowStartMilliseconds     uint16 = 152
	ieFlowEndMilliseconds       uint16 = 153
)

// Config holds the operator-supplied knobs.
type Config struct {
	// Endpoint is "host:port" of the collector. Empty disables the exporter.
	Endpoint string
	// Interval is the period between exports. Defaults to 30s.
	Interval time.Duration
	// DomainID is the IPFIX Observation Domain ID. Defaults to a stable
	// hash of the local hostname so multiple Testudo instances on the same
	// collector are distinguishable.
	DomainID uint32
	// TemplateEvery re-sends the template every N data exports so a
	// collector that misses the initial template can recover. Defaults to 10.
	TemplateEvery int
}

// FlowRec is the input shape — one bidirectional flow worth of data. The
// exporter handles only IPv4 endpoints; v6 records are filtered out.
type FlowRec struct {
	SrcIP   net.IP
	DstIP   net.IP
	SrcPort uint16
	DstPort uint16
	Proto   uint8 // IANA protocol number (6=tcp, 17=udp, etc.)
	Bytes   uint64
	Packets uint64
	Start   time.Time
	End     time.Time
}

// Exporter is the live UDP-bound exporter instance.
type Exporter struct {
	cfg          Config
	conn         net.Conn
	seq          uint32
	exports      int // count of Export calls; used to throttle template re-emit
}

// NewExporter dials the collector and returns a ready exporter. Pass an
// empty endpoint to get ErrDisabled.
func NewExporter(cfg Config) (*Exporter, error) {
	if cfg.Endpoint == "" {
		return nil, ErrDisabled
	}
	if cfg.Interval <= 0 {
		cfg.Interval = 30 * time.Second
	}
	if cfg.TemplateEvery <= 0 {
		cfg.TemplateEvery = 10
	}
	if cfg.DomainID == 0 {
		cfg.DomainID = defaultDomainID()
	}
	conn, err := net.Dial("udp", cfg.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", cfg.Endpoint, err)
	}
	return &Exporter{cfg: cfg, conn: conn}, nil
}

// ErrDisabled is returned when the exporter is asked to run with no
// configured endpoint. Callers can swallow it as a benign no-op.
var ErrDisabled = errors.New("ipfix: no endpoint configured")

// Endpoint reports the configured collector address.
func (e *Exporter) Endpoint() string { return e.cfg.Endpoint }

// Close releases the UDP socket.
func (e *Exporter) Close() error {
	if e == nil || e.conn == nil {
		return nil
	}
	return e.conn.Close()
}

// Export builds one IPFIX message containing the data records for the
// supplied flows. The template is re-emitted every cfg.TemplateEvery
// calls. IPv6 flows are silently skipped.
//
// Returns nil when there is nothing to send (no v4 flows, no template due).
func (e *Exporter) Export(flows []FlowRec) error {
	if e == nil || e.conn == nil {
		return ErrDisabled
	}
	var v4 []FlowRec
	for _, f := range flows {
		if f.SrcIP.To4() != nil && f.DstIP.To4() != nil {
			v4 = append(v4, f)
		}
	}
	sendTemplate := e.exports%e.cfg.TemplateEvery == 0

	if !sendTemplate && len(v4) == 0 {
		return nil
	}

	body := new(bytes.Buffer)
	if sendTemplate {
		if err := writeTemplateSet(body); err != nil {
			return err
		}
	}
	if len(v4) > 0 {
		if err := writeDataSet(body, v4); err != nil {
			return err
		}
	}
	if body.Len() == 0 {
		return nil
	}

	totalLen := 16 + body.Len() // 16-byte message header
	header := make([]byte, 16)
	binary.BigEndian.PutUint16(header[0:2], versionIPFIX)
	binary.BigEndian.PutUint16(header[2:4], uint16(totalLen))
	binary.BigEndian.PutUint32(header[4:8], uint32(time.Now().Unix()))
	binary.BigEndian.PutUint32(header[8:12], e.seq)
	binary.BigEndian.PutUint32(header[12:16], e.cfg.DomainID)

	msg := append(header, body.Bytes()...)
	if _, err := e.conn.Write(msg); err != nil {
		return fmt.Errorf("ipfix write: %w", err)
	}
	e.seq += uint32(len(v4))
	e.exports++
	return nil
}

// writeTemplateSet emits the template-set bytes onto b.
func writeTemplateSet(b *bytes.Buffer) error {
	tmpl := []struct {
		IE  uint16
		Len uint16
	}{
		{ieSourceIPv4Address, 4},
		{ieDestinationIPv4Address, 4},
		{ieSourceTransportPort, 2},
		{ieDestinationTransportPort, 2},
		{ieProtocolIdentifier, 1},
		{iePacketDeltaCount, 8},
		{ieOctetDeltaCount, 8},
		{ieFlowStartMilliseconds, 8},
		{ieFlowEndMilliseconds, 8},
	}
	const setHdrLen = 4
	const tmplHdrLen = 4
	const fieldLen = 4
	setLen := setHdrLen + tmplHdrLen + fieldLen*len(tmpl)

	if err := binary.Write(b, binary.BigEndian, setIDTemplate); err != nil {
		return err
	}
	if err := binary.Write(b, binary.BigEndian, uint16(setLen)); err != nil {
		return err
	}
	if err := binary.Write(b, binary.BigEndian, templateID); err != nil {
		return err
	}
	if err := binary.Write(b, binary.BigEndian, uint16(len(tmpl))); err != nil {
		return err
	}
	for _, f := range tmpl {
		if err := binary.Write(b, binary.BigEndian, f.IE); err != nil {
			return err
		}
		if err := binary.Write(b, binary.BigEndian, f.Len); err != nil {
			return err
		}
	}
	return nil
}

// writeDataSet emits the data-set bytes onto b. Record layout MUST match
// the order/widths declared in writeTemplateSet.
func writeDataSet(b *bytes.Buffer, flows []FlowRec) error {
	const recordLen = 4 + 4 + 2 + 2 + 1 + 8 + 8 + 8 + 8 // = 45 bytes
	const setHdrLen = 4
	setLen := setHdrLen + recordLen*len(flows)
	if err := binary.Write(b, binary.BigEndian, templateID); err != nil {
		return err
	}
	if err := binary.Write(b, binary.BigEndian, uint16(setLen)); err != nil {
		return err
	}
	for _, f := range flows {
		src4 := f.SrcIP.To4()
		dst4 := f.DstIP.To4()
		if src4 == nil || dst4 == nil {
			continue
		}
		b.Write(src4)
		b.Write(dst4)
		_ = binary.Write(b, binary.BigEndian, f.SrcPort)
		_ = binary.Write(b, binary.BigEndian, f.DstPort)
		b.WriteByte(f.Proto)
		_ = binary.Write(b, binary.BigEndian, f.Packets)
		_ = binary.Write(b, binary.BigEndian, f.Bytes)
		_ = binary.Write(b, binary.BigEndian, uint64(f.Start.UnixMilli()))
		_ = binary.Write(b, binary.BigEndian, uint64(f.End.UnixMilli()))
	}
	return nil
}

func defaultDomainID() uint32 {
	h := fnv.New32a()
	if hn, err := os.Hostname(); err == nil {
		_, _ = h.Write([]byte(strings.ToLower(hn)))
	} else {
		_, _ = h.Write([]byte("testudo"))
	}
	// Domain ID 0 is reserved per RFC; nudge if our hash lands there.
	v := h.Sum32()
	if v == 0 {
		v = 1
	}
	return v
}
