// Package logexport sends Testudo's records to a log collector or SIEM:
// syslog (RFC 5424) or CEF over UDP, TCP or TLS, or JSON lines. Records
// wait in a bounded queue; when the collector is slow or away, the oldest
// are dropped and counted, and the connection is made again with a
// backoff. Nothing here blocks the code that produces records.
package logexport

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Categories of records.
const (
	Firewall = "firewall" // logged packets
	Alerts   = "alerts"   // anomalies and incidents
	Audit    = "audit"    // privileged operations, logins, settings
	Access   = "access"   // access requests, grants, break-glass
	Config   = "config"   // changes of the configuration model
)

// Syslog severities (RFC 5424).
const (
	SevCritical = 2
	SevError    = 3
	SevWarning  = 4
	SevNotice   = 5
	SevInfo     = 6
)

// Record is one thing to send.
type Record struct {
	Time     time.Time
	Category string
	Severity int
	// Event names what happened, briefly ("drop", "login", "change").
	Event   string
	Message string
	Fields  map[string]string
}

// Target is where and how records go.
type Target struct {
	Name       string
	Address    string // host:port
	Transport  string // udp, tcp, tls
	Format     string // rfc5424, cef, json
	Categories []string
	Facility   int // syslog facility, 16..23 for local0..local7
	// CA is a PEM bundle the TLS server's certificate must chain to; empty
	// uses the system's roots. ServerName overrides the name checked.
	CA         []byte
	ServerName string
}

// Wants reports whether the target takes records of the category.
func (t Target) Wants(category string) bool { return slices.Contains(t.Categories, category) }

// Status is what an exporter reports.
type Status struct {
	Name      string    `json:"name"`
	Address   string    `json:"address"`
	Connected bool      `json:"connected"`
	Sent      uint64    `json:"sent"`
	Dropped   uint64    `json:"dropped"`
	LastError string    `json:"last_error,omitempty"`
	LastSent  time.Time `json:"last_sent,omitzero"`
}

// QueueSize is how many records wait at most.
const QueueSize = 4096

// Exporter sends to one target.
type Exporter struct {
	t    Target
	host string

	mu     sync.Mutex
	queue  [][]byte
	status Status
	wake   chan struct{}
}

// New makes an exporter; host names this node in the records.
func New(t Target, host string) *Exporter {
	return &Exporter{t: t, host: host, wake: make(chan struct{}, 1), status: Status{Name: t.Name, Address: t.Address}}
}

// Target returns what the exporter was made for.
func (x *Exporter) Target() Target { return x.t }

// Status returns the exporter's counters.
func (x *Exporter) Status() Status {
	x.mu.Lock()
	defer x.mu.Unlock()
	return x.status
}

// Send queues a record the target wants; it never blocks.
func (x *Exporter) Send(r Record) {
	if !x.t.Wants(r.Category) {
		return
	}
	msg := x.encode(r)
	x.mu.Lock()
	if len(x.queue) >= QueueSize {
		x.queue = x.queue[1:]
		x.status.Dropped++
	}
	x.queue = append(x.queue, msg)
	x.mu.Unlock()
	select {
	case x.wake <- struct{}{}:
	default:
	}
}

func (x *Exporter) encode(r Record) []byte {
	switch x.t.Format {
	case "cef":
		return RFC5424(r, x.host, x.t.Facility, CEF(r))
	case "json":
		return JSON(r, x.host)
	default:
		return RFC5424(r, x.host, x.t.Facility, "")
	}
}

// Run sends until ctx ends.
func (x *Exporter) Run(ctx context.Context) {
	backoff := time.Second
	for ctx.Err() == nil {
		conn, err := x.dial(ctx)
		if err != nil {
			x.fail(err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			backoff = min(backoff*2, 30*time.Second)
			continue
		}
		backoff = time.Second
		x.mu.Lock()
		x.status.Connected, x.status.LastError = true, ""
		x.mu.Unlock()
		err = x.pump(ctx, conn)
		conn.Close()
		x.mu.Lock()
		x.status.Connected = false
		x.mu.Unlock()
		if err != nil && ctx.Err() == nil {
			x.fail(err)
		}
	}
}

func (x *Exporter) fail(err error) {
	x.mu.Lock()
	x.status.LastError = err.Error()
	x.mu.Unlock()
}

func (x *Exporter) dial(ctx context.Context) (net.Conn, error) {
	d := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	switch x.t.Transport {
	case "udp":
		return d.DialContext(ctx, "udp", x.t.Address)
	case "tcp":
		return d.DialContext(ctx, "tcp", x.t.Address)
	case "tls":
		cfg := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: x.t.ServerName}
		if cfg.ServerName == "" {
			cfg.ServerName, _, _ = net.SplitHostPort(x.t.Address)
		}
		if len(x.t.CA) > 0 {
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(x.t.CA) {
				return nil, errors.New("the CA bundle holds no certificate")
			}
			cfg.RootCAs = pool
		}
		return (&tls.Dialer{NetDialer: d, Config: cfg}).DialContext(ctx, "tcp", x.t.Address)
	}
	return nil, fmt.Errorf("unknown transport %q", x.t.Transport)
}

// pump writes queued records until the connection fails or ctx ends.
func (x *Exporter) pump(ctx context.Context, conn net.Conn) error {
	for {
		x.mu.Lock()
		batch := x.queue
		x.queue = nil
		x.mu.Unlock()
		for i, msg := range batch {
			_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if _, err := conn.Write(x.frame(msg)); err != nil {
				// What was not written goes back to the front.
				x.mu.Lock()
				x.queue = append(append([][]byte(nil), batch[i:]...), x.queue...)
				if over := len(x.queue) - QueueSize; over > 0 {
					x.queue = x.queue[over:]
					x.status.Dropped += uint64(over)
				}
				x.mu.Unlock()
				return err
			}
			x.mu.Lock()
			x.status.Sent++
			x.status.LastSent = time.Now()
			x.mu.Unlock()
		}
		select {
		case <-ctx.Done():
			return nil
		case <-x.wake:
		case <-time.After(30 * time.Second):
		}
	}
}

// frame wraps a message for the transport: one datagram each over UDP;
// over a stream, octet counting for syslog (RFC 6587) and a line for JSON.
func (x *Exporter) frame(msg []byte) []byte {
	if x.t.Transport == "udp" {
		return msg
	}
	if x.t.Format == "json" {
		return append(append([]byte(nil), msg...), '\n')
	}
	return append([]byte(strconv.Itoa(len(msg))+" "), msg...)
}

// sortedKeys keeps the output of a record stable.
func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// RFC5424 formats a syslog message. With body set (CEF), the body is the
// message; otherwise the fields go into a structured-data element.
func RFC5424(r Record, host string, facility int, body string) []byte {
	if facility == 0 {
		facility = 20 // local4
	}
	var b bytes.Buffer
	fmt.Fprintf(&b, "<%d>1 %s %s testudo - %s ", facility*8+r.Severity, r.Time.UTC().Format("2006-01-02T15:04:05.000000Z"),
		nilValue(host), nilValue(r.Category))
	if body != "" {
		b.WriteString("- ")
		b.WriteString(body)
		return b.Bytes()
	}
	if len(r.Fields) == 0 {
		b.WriteString("-")
	} else {
		// 32473 is the private enterprise number reserved for examples
		// (RFC 5612); collectors key on the name before it.
		b.WriteString("[testudo@32473")
		fmt.Fprintf(&b, ` event="%s"`, sdEscape(r.Event))
		for _, k := range sortedKeys(r.Fields) {
			fmt.Fprintf(&b, ` %s="%s"`, sdName(k), sdEscape(r.Fields[k]))
		}
		b.WriteString("]")
	}
	if r.Message != "" {
		b.WriteString(" ")
		b.WriteString(r.Message)
	}
	return b.Bytes()
}

func nilValue(s string) string {
	if s == "" {
		return "-"
	}
	return strings.Map(func(r rune) rune {
		if r <= 32 || r >= 127 {
			return '_'
		}
		return r
	}, s)
}

func sdName(s string) string {
	return strings.Map(func(r rune) rune {
		if r <= 32 || r >= 127 || r == '=' || r == ']' || r == '"' {
			return '_'
		}
		return r
	}, s)
}

func sdEscape(s string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, `]`, `\]`).Replace(s)
}

// cefKeys maps record fields to CEF's dictionary.
var cefKeys = map[string]string{
	"src": "src", "dst": "dst", "src_port": "spt", "dst_port": "dpt", "proto": "proto",
	"in_iface": "deviceInboundInterface", "out_iface": "deviceOutboundInterface",
	"action": "act", "actor": "suser", "rule": "cs1", "length": "in", "result": "outcome",
}

// CEF formats a record as ArcSight Common Event Format.
func CEF(r Record) string {
	sev := map[int]int{SevCritical: 10, SevError: 8, SevWarning: 6, SevNotice: 4, SevInfo: 2}[r.Severity]
	head := func(s string) string { return strings.NewReplacer(`\`, `\\`, `|`, `\|`).Replace(s) }
	ext := func(s string) string {
		return strings.NewReplacer(`\`, `\\`, `=`, `\=`, "\n", `\n`, "\r", `\r`).Replace(s)
	}
	name := r.Message
	if name == "" {
		name = r.Event
	}
	var parts []string
	for _, k := range sortedKeys(r.Fields) {
		key, ok := cefKeys[k]
		if !ok {
			continue
		}
		parts = append(parts, key+"="+ext(r.Fields[k]))
		if key == "cs1" {
			parts = append(parts, "cs1Label=rule")
		}
	}
	parts = append(parts, "rt="+strconv.FormatInt(r.Time.UnixMilli(), 10), "cat="+ext(r.Category))
	return fmt.Sprintf("CEF:0|Testudo|Testudo|1|%s|%s|%d|%s", head(r.Category+":"+r.Event), head(name), sev, strings.Join(parts, " "))
}

// JSON formats a record as one JSON object.
func JSON(r Record, host string) []byte {
	m := map[string]any{"time": r.Time.UTC().Format(time.RFC3339Nano), "host": host, "category": r.Category,
		"event": r.Event, "severity": r.Severity}
	if r.Message != "" {
		m["message"] = r.Message
	}
	for k, v := range r.Fields {
		if _, taken := m[k]; !taken {
			m[k] = v
		}
	}
	b, _ := json.Marshal(m)
	return b
}
