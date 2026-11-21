//go:build linux

package lbstage

import (
	"context"
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
	"github.com/noahzmr/testudo/internal/flowattr"
	"github.com/noahzmr/testudo/internal/lbrender"
	"github.com/noahzmr/testudo/internal/model"
	"github.com/noahzmr/testudo/internal/netops"
	"github.com/noahzmr/testudo/internal/testnet"
)

// TestProxyPrefersLocalBackends: a pool with a backend at this site and one
// at another. The local one gets the traffic; when its health check fails
// the other site's takes over, and gives it back when the local one is
// healthy again.
func TestProxyPrefersLocalBackends(t *testing.T) {
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
	var localDown atomic.Bool
	for name, addr := range map[string]string{"here": "10.50.0.2:8080", "there": "10.50.0.3:8080"} {
		var ln net.Listener
		testnet.Must(t, back.Do(func() error {
			var err error
			ln, err = net.Listen("tcp", addr)
			return err
		}))
		t.Cleanup(func() { ln.Close() })
		go http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if name == "here" && localDown.Load() && r.URL.Path == "/healthz" {
				http.Error(w, "down", http.StatusServiceUnavailable)
				return
			}
			fmt.Fprint(w, name)
		}))
	}

	dir := t.TempDir()
	nw := &netops.Writer{AllowWrites: true}
	stage := &Stage{Runner: nw, Dir: filepath.Join(dir, "proxy"), SecretsDir: filepath.Join(dir, "secrets"), APIAddr: "127.0.0.1:18089",
		AuthURL: "http://127.0.0.1:1/", Settle: 15 * time.Second, Locate: func(*confstore.State) (string, string) { return id(1), "" }}
	t.Cleanup(func() { nw.ProxyControl(netops.ProxyStop, "", "") })
	store, err := confstore.Open(filepath.Join(dir, "config"))
	testnet.Must(t, err)
	defer store.Close()
	eng, err := confapply.New(store, confapply.Options{Dir: dir, Window: time.Minute}, stage)
	testnet.Must(t, err)
	site := func(n int) model.Ref[model.Site] { return model.Ref[model.Site]{ID: id(n)} }
	var ops []confstore.Op
	for _, e := range []model.Entity{
		&model.Site{Meta: meta(1, "hq")}, &model.Site{Meta: meta(2, "branch")},
		&model.Zone{Meta: meta(10, "wan"), DefaultAction: "drop"},
		&model.LBBackendPool{Meta: meta(20, "app"), Algorithm: "weighted_round_robin",
			Backends:    []model.LBBackend{{Address: "10.50.0.2:8080", Site: site(1)}, {Address: "10.50.0.3:8080", Site: site(2)}},
			HealthCheck: model.LBHealthCheck{Type: "http", Path: "/healthz", Interval: "1s", Timeout: "1s"}},
		&model.LBService{Meta: meta(30, "web"), Enabled: true, Zone: model.Ref[model.Zone]{ID: id(10)}, Port: 8081, Protocol: "http", Mode: "proxy",
			DefaultPool: model.Ref[model.LBBackendPool]{ID: id(20)}},
	} {
		ops = append(ops, op(e))
	}
	if _, err := eng.Apply(context.Background(), "test", "", ops); err != nil {
		t.Fatal(err)
	}
	testnet.Must(t, eng.Confirm("test"))

	get := func() string {
		hc := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{DisableKeepAlives: true,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				var c net.Conn
				err := client.Do(func() error {
					var err error
					c, err = (&net.Dialer{}).DialContext(ctx, network, addr)
					return err
				})
				return c, err
			}}}
		res, err := hc.Get("http://192.0.2.1:8081/")
		if err != nil {
			return "error"
		}
		defer res.Body.Close()
		b, _ := io.ReadAll(res.Body)
		return string(b)
	}
	all := func(want string, within time.Duration) bool {
		for deadline := time.Now().Add(within); time.Now().Before(deadline); time.Sleep(300 * time.Millisecond) {
			ok := true
			for i := 0; i < 6; i++ {
				ok = ok && get() == want
			}
			if ok {
				return true
			}
		}
		return false
	}
	if !all("here", 15*time.Second) {
		t.Fatalf("the local backend does not get all the traffic: %q", get())
	}
	// The proxy's access log says which client went to which backend,
	// through which router: what flow attribution reads.
	entries := (&flowattr.AccessLog{Path: filepath.Join(stage.Dir, lbrender.AccessLogFile)}).Read(time.Now())
	found := false
	for _, e := range entries {
		if e.Backend == "10.50.0.2:8080" && strings.HasPrefix(e.Router, "svc-web-") && strings.HasPrefix(e.Client, "192.0.2.2:") {
			found = true
		}
	}
	if !found {
		t.Errorf("the access log has no usable entry: %+v", entries)
	}
	localDown.Store(true)
	if !all("there", 15*time.Second) {
		t.Fatalf("no failover to the other site: %q", get())
	}
	localDown.Store(false)
	if !all("here", 15*time.Second) {
		t.Fatalf("traffic did not come back: %q", get())
	}
}

func op(e model.Entity) confstore.Op {
	obj, _ := json.Marshal(e)
	return confstore.Op{Type: confstore.OpCreate, Kind: e.Kind(), ID: e.GetMeta().ID, Object: obj}
}
