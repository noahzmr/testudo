//go:build linux

package lbstage

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/noahzmr/testudo/internal/confapply"
	"github.com/noahzmr/testudo/internal/confstore"
	"github.com/noahzmr/testudo/internal/model"
	"github.com/noahzmr/testudo/internal/netops"
	"github.com/noahzmr/testudo/internal/pki"
	"github.com/noahzmr/testudo/internal/secrets"
	"github.com/noahzmr/testudo/internal/testnet"
)

var (
	_   confapply.Stage = (*Stage)(nil)
	_   Runner          = (*netops.Writer)(nil)
	ctx                 = context.Background()
)

func id(n int) string                    { return fmt.Sprintf("00000000-0000-4000-8000-%012d", n) }
func meta(n int, name string) model.Meta { return model.Meta{ID: id(n), Name: name} }

// TestProxyOnARealKernel runs the real proxy between a client namespace and
// two backends and checks what a client sees.
//
//	client 192.0.2.2 --- wan0 [proxy] lan0 --- backends 10.50.0.2 (a), 10.50.0.3 (b)
func TestProxyOnARealKernel(t *testing.T) {
	if _, err := exec.LookPath("traefik"); err != nil {
		t.Skip("traefik is not installed")
	}
	if testnet.Isolate(t) {
		return
	}
	client, back := testnet.NewNS(t, "client"), testnet.NewNS(t, "backends")
	testnet.Veth(t, "wan0", client, "eth0")
	testnet.Veth(t, "lan0", back, "eth0")
	testnet.Must(t, testnet.Addr("wan0", "192.0.2.1/24"))
	testnet.Must(t, testnet.Addr("lan0", "10.50.0.1/24"))
	testnet.Must(t, client.Do(func() error { return testnet.Addr("eth0", "192.0.2.2/24") }))
	testnet.Must(t, back.Do(func() error {
		if err := testnet.Addr("eth0", "10.50.0.2/24"); err != nil {
			return err
		}
		return testnet.Addr("eth0", "10.50.0.3/24")
	}))

	dir := t.TempDir()
	sec := secrets.Store{Dir: filepath.Join(dir, "secrets")}
	ca := pki.CA{Secrets: sec}
	listen := func(addr string) net.Listener {
		t.Helper()
		var ln net.Listener
		testnet.Must(t, back.Do(func() error {
			var err error
			ln, err = net.Listen("tcp", addr)
			return err
		}))
		t.Cleanup(func() { ln.Close() })
		return ln
	}
	// HTTP backends answer with their name; "a" can be switched off.
	var aDown atomic.Bool
	for name, addr := range map[string]string{"a": "10.50.0.2:8080", "b": "10.50.0.3:8080"} {
		name := name
		go http.Serve(listen(addr), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if name == "a" && aDown.Load() {
				http.Error(w, "down", http.StatusServiceUnavailable)
				return
			}
			fmt.Fprint(w, name)
		}))
	}
	// TLS backends for passthrough: each has its own certificate, so the
	// client can tell which one it reached and that nobody opened the TLS.
	for name, addr := range map[string]string{"a": "10.50.0.2:8443", "b": "10.50.0.3:8443"} {
		issued, err := ca.Issue([]string{name + ".example.com"})
		testnet.Must(t, err)
		pair, err := tls.X509KeyPair([]byte(issued.ChainPEM), issued.KeyPEM)
		testnet.Must(t, err)
		name := name
		go http.Serve(tls.NewListener(listen(addr), &tls.Config{Certificates: []tls.Certificate{pair}}),
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "tls-"+name) }))
	}
	// A plain backend behind TLS termination.
	go http.Serve(listen("10.50.0.3:9000"), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "plain-b") }))

	// The certificate the proxy terminates with comes from the internal CA.
	term, err := ca.Issue([]string{"app.example.com"})
	testnet.Must(t, err)
	testnet.Must(t, sec.Put("cert-app", term.KeyPEM))
	caPEM, _ := ca.Certificate()
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(caPEM)

	nw := &netops.Writer{AllowWrites: true}
	stage := &Stage{Runner: nw, Dir: filepath.Join(dir, "proxy"), SecretsDir: sec.Dir, APIAddr: "127.0.0.1:18089",
		AuthURL: "http://127.0.0.1:1/forward-auth", Settle: 15 * time.Second}
	t.Cleanup(func() { nw.ProxyControl(netops.ProxyStop, "", "") })
	store, err := confstore.Open(filepath.Join(dir, "config"))
	testnet.Must(t, err)
	defer store.Close()
	eng, err := confapply.New(store, confapply.Options{Dir: dir, Window: time.Minute}, stage)
	testnet.Must(t, err)

	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		var conn net.Conn
		err := client.Do(func() error {
			var err error
			conn, err = (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, network, addr)
			return err
		})
		return conn, err
	}
	get := func(url, host string, tlsConf *tls.Config) (string, *tls.ConnectionState) {
		hc := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{DialContext: dial, TLSClientConfig: tlsConf, DisableKeepAlives: true}}
		req, _ := http.NewRequest("GET", url, nil)
		if host != "" {
			req.Host = host
		}
		res, err := hc.Do(req)
		if err != nil {
			return "error: " + err.Error(), nil
		}
		defer res.Body.Close()
		body, _ := io.ReadAll(res.Body)
		if res.StatusCode != 200 {
			return fmt.Sprintf("status %d", res.StatusCode), res.TLS
		}
		return string(body), res.TLS
	}
	apply := func(note string, ops []confstore.Op) error {
		_, err := eng.Apply(ctx, "test", note, ops)
		if err == nil {
			err = eng.Confirm("test")
		}
		return err
	}
	create := func(objs ...model.Entity) []confstore.Op {
		var ops []confstore.Op
		for _, e := range objs {
			obj, _ := json.Marshal(e)
			ops = append(ops, confstore.Op{Type: confstore.OpCreate, Kind: e.Kind(), ID: e.GetMeta().ID, Object: obj})
		}
		return ops
	}
	pool := func(n int) model.Ref[model.LBBackendPool] { return model.Ref[model.LBBackendPool]{ID: id(n)} }
	svc := func(n int) model.Ref[model.LBService] { return model.Ref[model.LBService]{ID: id(n)} }
	zone := model.Ref[model.Zone]{ID: id(10)}

	if err := apply("load balancer", create(
		&model.Zone{Meta: meta(10, "wan"), DefaultAction: "drop"},
		&model.LBBackendPool{Meta: meta(20, "web"), Algorithm: "weighted_round_robin",
			Backends:    []model.LBBackend{{Address: "10.50.0.2:8080", Weight: 3}, {Address: "10.50.0.3:8080", Weight: 1}},
			HealthCheck: model.LBHealthCheck{Type: "http", Path: "/", Interval: "1s", Timeout: "1s"}},
		&model.LBBackendPool{Meta: meta(21, "tls-a"), Algorithm: "weighted_round_robin",
			Backends: []model.LBBackend{{Address: "10.50.0.2:8443"}}, HealthCheck: model.LBHealthCheck{Type: "none"}},
		&model.LBBackendPool{Meta: meta(22, "tls-b"), Algorithm: "weighted_round_robin",
			Backends: []model.LBBackend{{Address: "10.50.0.3:8443"}}, HealthCheck: model.LBHealthCheck{Type: "none"}},
		&model.LBBackendPool{Meta: meta(23, "plain-b"), Algorithm: "weighted_round_robin",
			Backends: []model.LBBackend{{Address: "10.50.0.3:9000"}}, HealthCheck: model.LBHealthCheck{Type: "none"}},
		&model.Certificate{Meta: meta(30, "app"), Source: "internal_ca", Domains: []string{"app.example.com"}, ChainPEM: term.ChainPEM, KeyRef: "cert-app"},
		&model.LBService{Meta: meta(40, "http"), Enabled: true, Zone: zone, Port: 8081, Protocol: "http", Mode: "proxy"},
		&model.LBService{Meta: meta(41, "tls"), Enabled: true, Zone: zone, Port: 8444, Protocol: "tcp", Mode: "proxy", DefaultPool: pool(22)},
		&model.LBRouter{Meta: meta(50, "web"), Enabled: true, Service: svc(40), Hosts: []string{"app.example.com"}, TLS: "none", Pool: pool(20)},
		&model.LBRouter{Meta: meta(51, "sni-a"), Enabled: true, Service: svc(41), SNI: []string{"a.example.com"}, TLS: "passthrough", Pool: pool(21)},
		&model.LBRouter{Meta: meta(52, "sni-b"), Enabled: true, Service: svc(41), SNI: []string{"*.b.example.com", "b.example.com"}, TLS: "passthrough", Pool: pool(22)},
		&model.LBRouter{Meta: meta(53, "sni-term"), Enabled: true, Service: svc(41), SNI: []string{"app.example.com"}, TLS: "terminate",
			Certificate: model.Ref[model.Certificate]{ID: id(30)}, Pool: pool(23)},
	)); err != nil {
		t.Fatalf("apply: %v", err)
	}

	// 1. Host routing and weighted round robin: 3 to 1.
	count := map[string]int{}
	for i := 0; i < 40; i++ {
		body, _ := get("http://192.0.2.1:8081/", "app.example.com", nil)
		count[body]++
	}
	if count["a"] != 30 || count["b"] != 10 {
		t.Errorf("weighted round robin 3:1 over 40 requests: %v", count)
	}
	if body, _ := get("http://192.0.2.1:8081/", "other.example.com", nil); body != "status 404" {
		t.Errorf("a host no router matches: %q", body)
	}

	// 2. SNI passthrough: the client sees the backend's own certificate.
	for sni, want := range map[string]string{"a.example.com": "a", "b.example.com": "b", "x.b.example.com": "b"} {
		body, state := get("https://192.0.2.1:8444/", "", &tls.Config{ServerName: sni, InsecureSkipVerify: true})
		if body != "tls-"+want || state == nil || state.PeerCertificates[0].Subject.CommonName != want+".example.com" {
			cn := ""
			if state != nil {
				cn = state.PeerCertificates[0].Subject.CommonName
			}
			t.Errorf("passthrough for %s: body %q, certificate of %q", sni, body, cn)
		}
	}
	// 3. SNI termination: the proxy presents the internal CA's certificate,
	//    which verifies, and forwards to a plain backend.
	body, state := get("https://192.0.2.1:8444/", "", &tls.Config{ServerName: "app.example.com", RootCAs: roots})
	if body != "plain-b" || state == nil || state.PeerCertificates[0].Subject.CommonName != "app.example.com" {
		t.Errorf("termination: body %q", body)
	}
	// An unknown name falls through to the service's fallback pool.
	if body, _ := get("https://192.0.2.1:8444/", "", &tls.Config{ServerName: "unknown.example.org", InsecureSkipVerify: true}); body != "tls-b" {
		t.Errorf("fallback pool: %q", body)
	}

	// 4. Health-check failover: backend a starts failing; within a few
	//    checks everything goes to b.
	aDown.Store(true)
	onlyB := false
	for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline) && !onlyB; time.Sleep(300 * time.Millisecond) {
		onlyB = true
		for i := 0; i < 8; i++ {
			if body, _ := get("http://192.0.2.1:8081/", "app.example.com", nil); body != "b" {
				onlyB = false
			}
		}
	}
	if !onlyB {
		t.Error("requests still reach the failing backend after the health check had time to notice")
	}
	state5, err := stage.State(ctx)
	if err != nil || state5[id(20)].Requests < 40 || state5[id(20)].Backends["10.50.0.2:8080"] != "DOWN" || state5[id(20)].Backends["10.50.0.3:8080"] != "UP" {
		t.Errorf("pool state: %+v, %v", state5[id(20)], err)
	}
	aDown.Store(false)

	// 5. A configuration the proxy refuses is rolled back, and the previous
	//    one keeps serving.
	err = apply("broken middleware", create(
		&model.Middleware{Meta: meta(60, "bad-breaker"), Type: "circuit_breaker", Settings: map[string]string{"expression": "NoSuchFunction() >"}},
		&model.LBRouter{Meta: meta(54, "broken"), Enabled: true, Service: svc(40), Hosts: []string{"broken.example.com"}, TLS: "none",
			Pool: pool(20), Middlewares: []model.Ref[model.Middleware]{{ID: id(60)}}},
	))
	if err == nil || !strings.Contains(err.Error(), "refused") {
		t.Errorf("a configuration the proxy cannot use: %v", err)
	}
	if _, ok := store.Current().Get(model.KindLBRouter, id(54)); ok {
		t.Error("the refused router stayed in the model")
	}
	ok := false
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline) && !ok; time.Sleep(300 * time.Millisecond) {
		body, _ := get("http://192.0.2.1:8081/", "app.example.com", nil)
		ok = body == "a" || body == "b"
	}
	if !ok {
		t.Error("after the rollback the previous configuration does not serve")
	}

	// 6. Removing every service stops the proxy.
	var del []confstore.Op
	for _, kind := range []model.Kind{model.KindLBRouter, model.KindLBService} {
		for _, e := range store.Current().List(kind) {
			del = append(del, confstore.Op{Type: confstore.OpDelete, Kind: kind, ID: e.GetMeta().ID, IfMatch: e.GetMeta().Version})
		}
	}
	if err := apply("remove", del); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if st, _ := nw.ProxyState(); st != "stopped" {
		t.Errorf("proxy state after removing every service: %s", st)
	}
	if body, _ := get("http://192.0.2.1:8081/", "app.example.com", nil); !strings.HasPrefix(body, "error") {
		t.Errorf("the listener is still up: %q", body)
	}
}
