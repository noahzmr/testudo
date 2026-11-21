package logexport

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

var at = time.Date(2026, 11, 21, 18, 30, 0, 0, time.UTC)

func drop() Record {
	return Record{Time: at, Category: Firewall, Severity: SevNotice, Event: "drop", Message: "packet dropped",
		Fields: map[string]string{"rule": `default "drop"`, "src": "192.0.2.10", "dst": "198.51.100.7", "dst_port": "443", "proto": "tcp", "action": "drop"}}
}

func TestFormats(t *testing.T) {
	got := string(RFC5424(drop(), "fw1", 20, ""))
	want := `<165>1 2026-11-21T18:30:00.000000Z fw1 testudo - firewall [testudo@32473 event="drop" action="drop" dst="198.51.100.7" dst_port="443" proto="tcp" rule="default \"drop\"" src="192.0.2.10"] packet dropped`
	if got != want {
		t.Errorf("rfc5424:\n got %s\nwant %s", got, want)
	}
	cef := CEF(drop())
	for _, w := range []string{"CEF:0|Testudo|Testudo|1|firewall:drop|packet dropped|4|", "dpt=443", "src=192.0.2.10", "act=drop", `cs1=default "drop"`, "cs1Label=rule"} {
		if !strings.Contains(cef, w) {
			t.Errorf("cef lacks %q: %s", w, cef)
		}
	}
	var m map[string]any
	if err := json.Unmarshal(JSON(drop(), "fw1"), &m); err != nil || m["dst_port"] != "443" || m["host"] != "fw1" || m["category"] != "firewall" {
		t.Errorf("json: %v %v", m, err)
	}
	// Only the categories asked for.
	x := New(Target{Categories: []string{Audit}}, "fw1")
	x.Send(drop())
	if len(x.queue) != 0 {
		t.Error("a firewall record was queued for an audit-only target")
	}
}

// TestStreamsAndDatagrams: records reach a collector over UDP, over TCP
// with octet counting, and over TLS with the collector's CA.
func TestStreamsAndDatagrams(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// UDP.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	x := New(Target{Name: "u", Address: pc.LocalAddr().String(), Transport: "udp", Format: "rfc5424", Categories: []string{Firewall}}, "fw1")
	go x.Run(ctx)
	x.Send(drop())
	buf := make([]byte, 2048)
	pc.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _, err := pc.ReadFrom(buf)
	if err != nil || !strings.HasPrefix(string(buf[:n]), "<165>1 ") {
		t.Fatalf("udp: %v %q", err, buf[:n])
	}

	// TLS (TCP framing underneath).
	cert, caPEM := selfSigned(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan string, 2)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		r := bufio.NewReader(c)
		for i := 0; i < 2; i++ {
			lenStr, err := r.ReadString(' ')
			if err != nil {
				return
			}
			n, _ := strconv.Atoi(strings.TrimSpace(lenStr))
			msg := make([]byte, n)
			if _, err := io.ReadFull(r, msg); err != nil {
				return
			}
			got <- string(msg)
		}
	}()
	y := New(Target{Name: "s", Address: ln.Addr().String(), Transport: "tls", Format: "cef", Categories: []string{Firewall, Audit},
		CA: caPEM, ServerName: "collector.test"}, "fw1")
	go y.Run(ctx)
	y.Send(drop())
	y.Send(Record{Time: at, Category: Audit, Severity: SevNotice, Event: "login", Fields: map[string]string{"actor": "alice", "result": "ok"}})
	for _, want := range []string{"CEF:0|Testudo|Testudo|1|firewall:drop", "suser=alice"} {
		select {
		case m := <-got:
			if !strings.Contains(m, want) {
				t.Errorf("tls: %q lacks %q", m, want)
			}
		case <-ctx.Done():
			t.Fatalf("tls: nothing arrived; %+v", y.Status())
		}
	}
	if st := y.Status(); st.Sent != 2 || !st.Connected {
		t.Errorf("status: %+v", st)
	}
}

// TestAWrongCAIsRefused: a collector whose certificate does not chain to
// the CA gets nothing.
func TestAWrongCAIsRefused(t *testing.T) {
	cert, _ := selfSigned(t)
	_, otherCA := selfSigned(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.(*tls.Conn).Handshake()
			c.Close()
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	x := New(Target{Address: ln.Addr().String(), Transport: "tls", Format: "json", Categories: []string{Firewall}, CA: otherCA, ServerName: "collector.test"}, "fw1")
	go x.Run(ctx)
	x.Send(drop())
	<-ctx.Done()
	if st := x.Status(); st.Sent != 0 || !strings.Contains(st.LastError, "certificate") {
		t.Errorf("status: %+v", st)
	}
}

func selfSigned(t *testing.T) (tls.Certificate, []byte) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "collector.test"},
		DNSNames: []string{"collector.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	kb, _ := x509.MarshalECPrivateKey(key)
	cert, err := tls.X509KeyPair(pemCert, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}))
	if err != nil {
		t.Fatal(err)
	}
	return cert, pemCert
}
