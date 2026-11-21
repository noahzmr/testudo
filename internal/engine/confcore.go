package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/noahzmr/testudo/internal/aliasfeed"
	"github.com/noahzmr/testudo/internal/confapply"
	"github.com/noahzmr/testudo/internal/config"
	"github.com/noahzmr/testudo/internal/confstore"
	"github.com/noahzmr/testudo/internal/frrender"
	"github.com/noahzmr/testudo/internal/frrstage"
	"github.com/noahzmr/testudo/internal/fwrender"
	"github.com/noahzmr/testudo/internal/gwmon"
	"github.com/noahzmr/testudo/internal/harender"
	"github.com/noahzmr/testudo/internal/hastage"
	"github.com/noahzmr/testudo/internal/identity"
	"github.com/noahzmr/testudo/internal/ifstage"
	"github.com/noahzmr/testudo/internal/lbhealth"
	"github.com/noahzmr/testudo/internal/lbstage"
	"github.com/noahzmr/testudo/internal/model"
	"github.com/noahzmr/testudo/internal/netops"
	"github.com/noahzmr/testudo/internal/pathmon"
	"github.com/noahzmr/testudo/internal/pki"
	"github.com/noahzmr/testudo/internal/secrets"
	"github.com/noahzmr/testudo/internal/storage"
	"github.com/noahzmr/testudo/internal/svcstage"
	"github.com/noahzmr/testudo/internal/wgstage"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// confCore is the configuration model's runtime: the versioned store and the
// transactional apply engine. The packet filter is driven by the model
// through internal/fwbridge; routing, VPN and proxy stages are added as those
// subsystems move onto the model.
type confCore struct {
	store  *confstore.Store
	apply  *confapply.Engine
	err    error
	notify atomic.Pointer[func(confapply.Notice)]
	// feed holds the content of URL-table and GeoIP aliases.
	feed *aliasfeed.Feed
	// wg is the WireGuard stage; secrets holds its keys on this node.
	wg *wgstage.Stage
	// ifaces configures the node's devices: addresses, DHCP clients, MTU,
	// link state.
	ifaces  *ifstage.Stage
	secrets secrets.Store
	// routing is the routing stage; gateways watches the gateways whose
	// health decides which routes it renders.
	routing  *frrstage.Stage
	gateways *gwmon.Monitor
	// routingState caches what the routing daemon reports, so that showing
	// it does not run a command per request.
	routingMu    sync.Mutex
	routingState map[string]any
	routingAt    time.Time
	// ha keeps an HA pair's addresses and connection state with whichever
	// member is alive.
	ha *hastage.Stage
	// services runs DHCP, router advertisements, DNS and NTP; names keeps
	// the names of DHCP clients in the resolver.
	services *svcstage.Stage
	names    *svcstage.Names
	// proxy is the load-balancer stage; forwardAuth answers the proxy's
	// questions about logins on a loopback listener of its own.
	proxy       *lbstage.Stage
	backends    *lbhealth.Monitor
	forwardAuth atomic.Pointer[http.Handler]
	proxyMu     sync.Mutex
	proxyState  map[string]any
	proxyAt     time.Time
	// started is set once the model has been applied after the start.
	started atomic.Bool
}

// Loopback addresses the proxy and this program talk on.
const (
	proxyAPIAddr    = "127.0.0.1:18089"
	forwardAuthAddr = "127.0.0.1:18090"
	// haRunDir holds the HA daemons' pid files and conntrackd's control
	// socket, whose path may not exceed 107 characters.
	haRunDir = "/run/testudo-ha"
	// svcRunDir holds the services' configuration, which daemons that drop
	// privileges read again on a reload, their pid files and sockets.
	svcRunDir = "/run/testudo-svc"
	// ifRunDir is where the DHCP clients of interfaces are supervised
	// from; their own pid and lease files are where the client keeps them.
	ifRunDir = "/run/testudo-if"
)

// ConfigDir is where the configuration log and the pending-apply marker live.
func ConfigDir(cfg config.Config) string { return filepath.Join(cfg.StorageDir, "config") }

func (e *Engine) openConfig() {
	c := &e.conf
	dir := ConfigDir(e.cfg)
	if c.store, c.err = confstore.OpenWait(dir, 5*time.Second); c.err != nil {
		log.Printf("config: model store unavailable: %v", c.err)
		return
	}
	// The packet filter is the first subsystem the model drives: through
	// the nftables stage where nft can be run with privileges, through the
	// bridge into the netlink path otherwise.
	c.feed = aliasfeed.New(filepath.Join(dir, "alias-cache.json"))
	c.feed.GeoDBDir = func() string { return e.settings.Snapshot().MaxMindDBDir }
	c.backends = &lbhealth.Monitor{}
	e.fwNft.Locate, e.fwNft.Elements, e.fwNft.BackendDown = e.locate, c.feed.Snapshot, c.backends.Down
	var stage confapply.Stage = e.fwNft
	// WireGuard devices come first: the packet filter names them and the
	// routing daemon routes through them.
	c.secrets = secrets.Store{Dir: filepath.Join(e.cfg.StorageDir, "secrets")}
	// On a cluster member a secret has to reach the other members too. The
	// hook is installed now because the stages below copy the store.
	local := c.secrets
	c.secrets.Replicate = func(name string, value []byte, remove bool) error {
		if mgr := e.cluster.mgr; mgr != nil && mgr.Node() != nil {
			return mgr.PutSecret(name, value, remove)
		}
		if remove {
			return local.Delete(name)
		}
		return local.Put(name, value)
	}
	// The devices come first: everything after them uses their addresses.
	c.ifaces = &ifstage.Stage{Locate: e.locate, Dir: filepath.Join(e.cfg.StorageDir, "interfaces"), RunDir: ifRunDir}
	if e.netops != nil {
		c.ifaces.Runner = e.netops
	}
	c.wg = &wgstage.Stage{Locate: e.locate, Secrets: c.secrets}
	if e.netops != nil {
		c.wg.Runner = e.netops
	}
	// Routing follows the packet filter: marks are set there and used here.
	c.gateways = &gwmon.Monitor{}
	e.fabric.paths = &pathmon.Monitor{}
	c.routing = &frrstage.Stage{Locate: e.locate, Down: c.gateways.Down, StateDir: dir, Paths: e.fabric.paths}
	if e.netops != nil {
		c.routing.Runner = e.netops
	}
	// An HA pair follows the packet filter, which lets VRRP and the state
	// sync in, and the routing it takes over with the addresses.
	c.ha = &hastage.Stage{Locate: e.locate, Dir: filepath.Join(e.cfg.StorageDir, "ha"), RunDir: haRunDir}
	if e.netops != nil {
		c.ha.Runner = e.netops
	}
	// The services come after the pair: they bind its virtual addresses.
	c.services = &svcstage.Stage{Locate: e.locate, Dir: filepath.Join(e.cfg.StorageDir, "services"), RunDir: svcRunDir,
		HooksDir: keaHooksDir()}
	c.names = &svcstage.Names{RunDir: svcRunDir}
	if e.netops != nil {
		c.services.Runner = e.netops
	}
	// The proxy comes last: its backends are reached over the routes and
	// tunnels the earlier stages set up.
	c.proxy = &lbstage.Stage{Locate: e.locate, Dir: filepath.Join(e.cfg.StorageDir, "proxy"), SecretsDir: c.secrets.Dir,
		APIAddr: proxyAPIAddr, AuthURL: "http://" + forwardAuthAddr + "/"}
	if e.netops != nil {
		c.proxy.Runner = e.netops
	}
	c.apply, c.err = confapply.New(c.store, confapply.Options{Dir: dir, Notify: e.configNotice}, c.ifaces, c.wg, stage, c.routing, c.ha, c.services, c.proxy)
	if c.err != nil {
		log.Printf("config: apply engine unavailable: %v", c.err)
		c.store.Close()
		c.store = nil
	}
}

// configNotice records every apply outcome in the audit log next to the
// kernel mutations, and forwards it to the web layer's event stream.
func (e *Engine) configNotice(n confapply.Notice) {
	result := "ok"
	if n.Err != nil {
		result = n.Err.Error()
	}
	if (n.Event == "applied" || n.Event == "confirmed") && n.Err == nil {
		// A start that failed is over once a change applies.
		e.conf.started.Store(true)
	}
	if n.Event == "confirmed" && n.Err == nil {
		go e.forgetDeletedUsers()
	}
	detail := map[string]any{"record": n.Index, "reason": n.Reason}
	// Say what changed. The values before and after are in the history
	// record the row names (GET /api/v1/history), with secrets masked.
	if n.Event == "applied" && e.conf.store != nil {
		if recs, err := e.conf.store.History(n.Index+1, 1); err == nil && len(recs) == 1 && recs[0].Index == n.Index {
			var changes []string
			for i, c := range recs[0].Changes {
				if i == 20 {
					changes = append(changes, fmt.Sprintf("and %d more", len(recs[0].Changes)-i))
					break
				}
				changes = append(changes, fmt.Sprintf("%s %s %s", c.Type, c.Kind, c.Name))
			}
			detail["changes"] = changes
		}
	}
	args, _ := json.Marshal(detail)
	// The engine lock is held by the caller; write the audit row off it.
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := e.store.InsertAudit(ctx, storage.AuditEntry{TS: time.Now(), Op: "config_" + n.Event,
			Args: string(args), Actor: n.Actor, Result: result}); err != nil {
			log.Printf("config: audit: %v", err)
		}
	}()
	if fn := e.conf.notify.Load(); fn != nil {
		(*fn)(n)
	}
}

// ConfigStore returns the configuration store, or nil with ConfigError set.
func (e *Engine) ConfigStore() *confstore.Store { return e.conf.store }

// ConfigApply returns the apply engine, or nil with ConfigError set.
func (e *Engine) ConfigApply() *confapply.Engine { return e.conf.apply }

// ConfigError says why the configuration model is unavailable.
func (e *Engine) ConfigError() error { return e.conf.err }

// SetConfigNotify registers the receiver of apply outcomes (the event stream).
func (e *Engine) SetConfigNotify(fn func(confapply.Notice)) { e.conf.notify.Store(&fn) }

// startConfig settles a change left unconfirmed by a previous run and brings
// the registered stages in line with the model.
func (e *Engine) startConfig(ctx context.Context) {
	if e.conf.apply == nil {
		return
	}
	if err := e.conf.apply.Start(ctx); err != nil {
		log.Printf("config: start: %v", err)
	} else {
		e.conf.started.Store(true)
	}
	e.seedRoles(ctx)
	e.prepareLocalUsers(ctx)
	e.migrateFirewallFile(ctx)
	e.migrateSettings(ctx)
	e.syncSettings(ctx)
	go e.grantLoop(ctx)
	if e.fwNft != nil {
		go e.aliasFeedLoop(ctx)
		go e.backendHealthLoop(ctx)
	}
	if e.netops != nil {
		go e.gatewayLoop(ctx)
		go e.peerExpiryLoop(ctx)
		go e.forwardAuthLoop(ctx)
		go e.serviceNamesLoop(ctx)
	}
}

// backendHealthLoop checks the backends of services balanced in the packet
// filter and reloads the ruleset when one changes state.
func (e *Engine) backendHealthLoop(ctx context.Context) {
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		st := e.conf.store.Current()
		site, node := e.locate(st)
		pools := fwrender.KernelBackends(st, fwrender.Options{SiteID: site, NodeID: node})
		if !e.conf.backends.Check(ctx, pools, time.Now()) {
			continue
		}
		for addr, s := range e.conf.backends.Status() {
			if s.Down {
				log.Printf("config: backend %s is down: %s", addr, s.Error)
			}
		}
		if _, pending := e.conf.apply.Pending(); pending {
			continue
		}
		if err := e.fwNft.Refresh(st); err != nil {
			log.Printf("config: reload after backend health change: %v", err)
		}
	}
}

// SetForwardAuth installs the handler that decides whether a request to a
// router that requires a login may pass. Without one every such request is
// refused.
func (e *Engine) SetForwardAuth(h http.Handler) { e.conf.forwardAuth.Store(&h) }

// forwardAuthLoop serves the proxy's login questions on loopback. It is a
// listener of its own so that the answer never depends on how the console
// is exposed, and it fails closed: no handler, no access.
func (e *Engine) forwardAuthLoop(ctx context.Context) {
	srv := &http.Server{Addr: forwardAuthAddr, ReadHeaderTimeout: 5 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if h := e.conf.forwardAuth.Load(); h != nil && *h != nil {
				(*h).ServeHTTP(w, r)
				return
			}
			http.Error(w, "this service requires a login, and no login service is configured", http.StatusForbidden)
		})}
	go func() {
		<-ctx.Done()
		srv.Close()
	}()
	if err := srv.ListenAndServe(); err != nil && ctx.Err() == nil {
		log.Printf("config: forward-auth listener: %v", err)
	}
}

// haRuntime reports this node's HA pair: whether it holds the virtual
// addresses now and whether both daemons run. Nil when the node is in no pair.
func (e *Engine) haRuntime() map[string]any {
	st := e.conf.store.Current()
	site, node := e.locate(st)
	res, err := harender.Render(st, harender.Options{SiteID: site, NodeID: node})
	if err != nil {
		return map[string]any{"error": err.Error()}
	}
	if !res.Enabled {
		return nil
	}
	active, held := hastage.Active(res.VirtualIPs)
	role := "standby"
	if active {
		role = "active"
	}
	out := map[string]any{"pair": res.Pair, "role": role, "virtual_ips": res.VirtualIPs, "held": held, "peer": res.Peer}
	daemons := map[string]string{}
	for _, d := range []string{"keepalived", "conntrackd"} {
		daemons[d] = "unavailable"
		if e.netops != nil {
			if s, err := e.netops.DaemonState(d, haRunDir); err == nil {
				daemons[d] = s
			}
		}
	}
	out["daemons"] = daemons
	return out
}

// proxyRuntime reports the proxy process and, per backend pool, its traffic
// and the health of its backends. The proxy is asked at most every five
// seconds.
func (e *Engine) proxyRuntime() map[string]any {
	c := &e.conf
	c.proxyMu.Lock()
	defer c.proxyMu.Unlock()
	if time.Since(c.proxyAt) > 5*time.Second {
		state := map[string]any{"process": "unavailable"}
		if e.netops != nil {
			if ps, err := e.netops.ProxyState(); err == nil {
				state["process"] = ps
				if ps == "running" {
					ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
					if pools, err := c.proxy.State(ctx); err == nil {
						state["pools"] = pools
					} else {
						state["error"] = err.Error()
					}
					cancel()
				}
			}
		}
		c.proxyState, c.proxyAt = state, time.Now()
	}
	return c.proxyState
}

// seedRoles creates the built-in roles the model does not have yet, so they
// can be assigned to users and groups from the first start. Roles change
// nothing in the running system, so the change is confirmed right away.
func (e *Engine) seedRoles(ctx context.Context) {
	if _, pending := e.conf.apply.Pending(); pending {
		return
	}
	var ops []confstore.Op
	for _, r := range identity.MissingBuiltinRoles(e.conf.store.Current()) {
		r.ID = confstore.NewID()
		obj, err := json.Marshal(r)
		if err != nil {
			return
		}
		ops = append(ops, confstore.Op{Type: confstore.OpCreate, Kind: model.KindRole, ID: r.ID, Object: obj})
	}
	if len(ops) == 0 {
		return
	}
	if _, err := e.conf.apply.Apply(ctx, "system", "built-in roles", ops); err != nil {
		log.Printf("config: create the built-in roles: %v", err)
		return
	}
	if err := e.conf.apply.Confirm("system"); err != nil {
		log.Printf("config: confirm the built-in roles: %v", err)
	}
}

// peerExpiryLoop removes peers from their devices when they expire.
func (e *Engine) peerExpiryLoop(ctx context.Context) {
	tick := time.NewTicker(30 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		if !e.conf.wg.Due() {
			continue
		}
		if _, pending := e.conf.apply.Pending(); pending {
			continue
		}
		st := e.conf.store.Current()
		if err := e.conf.wg.Refresh(ctx, st); err != nil {
			log.Printf("config: remove expired peers: %v", err)
			continue
		}
		log.Printf("config: expired WireGuard peers were removed from their tunnels")
		// The routes to an expired site-to-site peer go with it.
		if err := e.conf.routing.Refresh(ctx, st); err != nil {
			log.Printf("config: routes after peer expiry: %v", err)
		}
	}
}

// PAMLogin asks the host's PAM stack about a login, on the privileged
// side where there is one.
func (e *Engine) PAMLogin(user, password, code, from string) (netops.PAMResult, error) {
	req := netops.PAMRequest{User: user, Password: password, Code: code, RemoteHost: from}
	if e.netops != nil {
		return e.netops.PAMLogin(req)
	}
	return (&netops.Writer{}).PAMLogin(req)
}

// Secret reads an entry of the node's secret store.
func (e *Engine) Secret(ref string) ([]byte, error) { return e.conf.secrets.Get(ref) }

// StoreSecret puts a value into the node's secret store under a new name
// that starts with prefix, and returns the name.
func (e *Engine) StoreSecret(prefix string, value []byte) (string, error) {
	ref := prefix + "-" + confstore.NewID()
	return ref, e.conf.secrets.Put(ref, value)
}

// IssueCertificate issues a server certificate from the internal authority
// and keeps its key in the secret store.
func (e *Engine) IssueCertificate(names []string) (chainPEM, keyRef string, notAfter time.Time, err error) {
	issued, err := pki.CA{Secrets: e.conf.secrets}.Issue(names)
	if err != nil {
		return "", "", time.Time{}, err
	}
	keyRef = "cert-" + confstore.NewID()
	if err := e.conf.secrets.Put(keyRef, issued.KeyPEM); err != nil {
		return "", "", time.Time{}, err
	}
	return issued.ChainPEM, keyRef, issued.NotAfter, nil
}

// ImportCertificateKey stores the key of a certificate issued elsewhere
// once it is known to belong to that certificate.
func (e *Engine) ImportCertificateKey(chainPEM string, keyPEM []byte) (keyRef string, notAfter time.Time, err error) {
	if err := pki.CheckPair(chainPEM, keyPEM); err != nil {
		return "", time.Time{}, err
	}
	if notAfter, err = pki.NotAfter(chainPEM); err != nil {
		return "", time.Time{}, err
	}
	keyRef = "cert-" + confstore.NewID()
	return keyRef, notAfter, e.conf.secrets.Put(keyRef, keyPEM)
}

// CACertificate returns the internal authority's certificate.
func (e *Engine) CACertificate() ([]byte, error) {
	return pki.CA{Secrets: e.conf.secrets}.Certificate()
}

// certificateRuntime reports when each certificate held in the model
// expires. Certificates the proxy obtains by ACME are renewed by it and are
// not listed.
func (e *Engine) certificateRuntime() map[string]any {
	out := map[string]any{}
	for _, c := range e.conf.store.Current().List(model.KindCertificate) {
		cert := c.(*model.Certificate)
		if cert.ChainPEM == "" {
			continue
		}
		entry := map[string]any{}
		if na, err := pki.NotAfter(cert.ChainPEM); err == nil {
			entry["not_after"] = na
			entry["days_left"] = int(time.Until(na).Hours() / 24)
		} else {
			entry["error"] = "the certificate cannot be read"
		}
		out[cert.ID] = entry
	}
	return out
}

// NewTunnelKey creates a tunnel's private key in the secret store.
func (e *Engine) NewTunnelKey() (ref, publicKey string, err error) {
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return "", "", err
	}
	ref = "wg-" + confstore.NewID()
	if err := e.conf.secrets.Put(ref, []byte(key.String()+"\n")); err != nil {
		return "", "", err
	}
	return ref, key.PublicKey().String(), nil
}

// NewPresharedKey creates a preshared key in the secret store and returns
// it this one time.
func (e *Engine) NewPresharedKey() (ref, key string, err error) {
	psk, err := wgtypes.GenerateKey()
	if err != nil {
		return "", "", err
	}
	ref = "psk-" + confstore.NewID()
	if err := e.conf.secrets.Put(ref, []byte(psk.String()+"\n")); err != nil {
		return "", "", err
	}
	return ref, psk.String(), nil
}

// NewClientKeypair creates a key pair for a client device and keeps nothing.
func (e *Engine) NewClientKeypair() (privateKey, publicKey string, err error) {
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return "", "", err
	}
	return key.String(), key.PublicKey().String(), nil
}

// gatewayLoop probes the monitored gateways and moves routes when one goes
// down or comes back.
func (e *Engine) gatewayLoop(ctx context.Context) {
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		st := e.conf.store.Current()
		site, node := e.locate(st)
		gws := frrender.Gateways(st, frrender.Options{SiteID: site, NodeID: node})
		probeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		changed := e.conf.gateways.Check(probeCtx, gws, time.Now())
		cancel()
		if !changed {
			continue
		}
		for id, s := range e.conf.gateways.Status() {
			state := "up"
			if s.Down {
				state = "down"
			}
			log.Printf("config: gateway %s (monitor %s) is %s", id, s.Monitor, state)
		}
		if _, pending := e.conf.apply.Pending(); pending {
			continue // the pending change is settled first; the next round catches up
		}
		if err := e.conf.routing.Refresh(ctx, st); err != nil {
			log.Printf("config: move routes after gateway change: %v", err)
		}
	}
}

// routingRuntime reports gateway health and, when the routing daemon runs,
// its BGP sessions. The daemon is asked at most every five seconds.
func (e *Engine) routingRuntime() map[string]any {
	c := &e.conf
	out := map[string]any{"gateways": c.gateways.Status()}
	if e.netops == nil {
		return out
	}
	c.routingMu.Lock()
	defer c.routingMu.Unlock()
	if time.Since(c.routingAt) > 5*time.Second {
		state := map[string]any{"daemon": false}
		if raw, err := e.netops.FrrShow("bgp"); err == nil {
			state["daemon"] = true
			// {"ipv4Unicast": {"peers": {"<address>": {"state": ..., "pfxRcd": ...}}}, ...}
			var doc map[string]struct {
				Peers map[string]struct {
					State    string `json:"state"`
					Received int    `json:"pfxRcd"`
					Uptime   string `json:"peerUptime"`
				} `json:"peers"`
			}
			sessions := map[string]any{}
			if json.Unmarshal([]byte(raw), &doc) == nil {
				for _, fam := range doc {
					for addr, p := range fam.Peers {
						sessions[addr] = map[string]any{"state": p.State, "received": p.Received, "uptime": p.Uptime}
					}
				}
			}
			state["bgp"] = sessions
		}
		c.routingState, c.routingAt = state, time.Now()
	}
	for k, v := range c.routingState {
		out[k] = v
	}
	return out
}

// aliasFeedLoop refreshes run-time aliases and reloads the ruleset when their
// content changed.
func (e *Engine) aliasFeedLoop(ctx context.Context) {
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	for {
		st := e.conf.store.Current()
		var aliases []*model.Alias
		for _, a := range st.List(model.KindAlias) {
			aliases = append(aliases, a.(*model.Alias))
		}
		if e.conf.feed.Refresh(ctx, aliases, time.Now()) {
			if _, pending := e.conf.apply.Pending(); !pending {
				if err := e.fwNft.Refresh(st); err != nil {
					log.Printf("config: reload after alias refresh: %v", err)
				}
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// ConfigRuntime reports what the model's objects are doing in the running
// system: which packet-filter path is in use, per-object counters, and the
// state of run-time aliases.
func (e *Engine) ConfigRuntime() map[string]any {
	out := map[string]any{"packet_filter": "netlink"}
	if e.fwNft != nil {
		out["packet_filter"] = "nftables"
		if c, err := e.fwNft.Counters(); err == nil {
			out["counters"] = c
		} else {
			out["counters_error"] = err.Error()
		}
	}
	if e.conf.feed != nil {
		out["aliases"] = e.conf.feed.StatusOf()
	}
	if e.conf.gateways != nil {
		out["routing"] = e.routingRuntime()
	}
	if e.conf.store != nil {
		out["certificates"] = e.certificateRuntime()
	}
	if e.conf.store != nil {
		if f := e.fabricRuntime(); f != nil {
			out["fabric"] = f
		}
	}
	if e.conf.store != nil {
		if h := e.haRuntime(); h != nil {
			out["ha"] = h
		}
	}
	if sv := e.servicesRuntime(); sv != nil {
		out["services"] = sv
	}
	if e.conf.proxy != nil {
		lb := map[string]any{"backends": e.conf.backends.Status()}
		for k, v := range e.proxyRuntime() {
			lb[k] = v
		}
		out["load_balancer"] = lb
	}
	return out
}

// e.locate finds this machine in the model by host name. Until a node is
// defined, only objects with global scope apply here.
func (e *Engine) locate(st *confstore.State) (siteID, nodeID string) {
	host := strings.ToLower(e.cfg.NodeName)
	if host == "" {
		h, err := os.Hostname()
		if err != nil {
			return "", ""
		}
		host = strings.ToLower(h)
	}
	for _, e := range st.List(model.KindClusterNode) {
		n := e.(*model.ClusterNode)
		if strings.ToLower(n.Hostname) == host || strings.ToLower(n.Name) == host {
			return n.Site.ID, n.ID
		}
	}
	return "", ""
}
