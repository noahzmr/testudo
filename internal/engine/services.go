package engine

import (
	"context"
	"fmt"
	"log"
	"net"
	"path/filepath"
	"sort"
	"time"

	"github.com/noahzmr/testudo/internal/svcrender"
	"github.com/noahzmr/testudo/internal/svcstage"
)

// keaHooksDir finds Kea's hook libraries (the directory carries the
// architecture's triplet on Debian).
func keaHooksDir() string {
	if m, _ := filepath.Glob("/usr/lib/*/kea/hooks/libdhcp_lease_cmds.so"); len(m) > 0 {
		return filepath.Dir(m[0])
	}
	return "/usr/lib/x86_64-linux-gnu/kea/hooks"
}

// serviceNamesLoop keeps the names of DHCP clients in the resolver and in
// the flow view. Kea announces every name it records on the loopback; that
// wakes the loop at once, and it also runs every ten seconds, because the
// partner of an HA pair hands out leases this node only learns about.
func (e *Engine) serviceNamesLoop(ctx context.Context) {
	wake := make(chan struct{}, 1)
	if pc, err := net.ListenPacket("udp", net.JoinHostPort("127.0.0.1", "53001")); err == nil {
		defer pc.Close()
		go func() {
			buf := make([]byte, 4096)
			for {
				if _, _, err := pc.ReadFrom(buf); err != nil {
					return
				}
				// Kea has committed the lease when it sends the request.
				select {
				case wake <- struct{}{}:
				default:
				}
			}
		}()
	} else {
		log.Printf("services: name announcements from Kea: %v", err)
	}
	tick := time.NewTicker(10 * time.Second)
	defer tick.Stop()
	var lastErr string
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		case <-wake:
		}
		err := e.syncServiceNames(ctx)
		msg := ""
		if err != nil {
			msg = err.Error()
			// The resolver may have been restarted: begin from its file.
			e.conf.names.Forget()
		}
		if msg != lastErr && msg != "" {
			log.Printf("services: client names: %v", err)
		}
		lastErr = msg
	}
}

func (e *Engine) syncServiceNames(ctx context.Context) error {
	res := e.conf.services.Applied()
	if res == nil || !contains(res.Daemons, svcrender.DaemonUnbound) {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	leases, err := e.serviceLeases(ctx, res)
	if err != nil {
		return err
	}
	want := svcstage.DesiredNames(*res, leases, time.Now())
	if e.dnsCache != nil {
		for name, addrs := range want {
			for _, a := range addrs {
				e.dnsCache.RecordHostByIP(name, a)
			}
		}
	}
	return e.conf.names.Sync(ctx, want)
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// serviceLeases asks the running Kea servers for their leases.
func (e *Engine) serviceLeases(ctx context.Context, res *svcrender.Result) ([]svcstage.Lease, error) {
	var out []svcstage.Lease
	for _, f := range []struct {
		daemon string
		v6     bool
	}{{svcrender.DaemonKea4, false}, {svcrender.DaemonKea6, true}} {
		if !contains(res.Daemons, f.daemon) {
			continue
		}
		l, err := svcstage.Leases(ctx, svcRunDir, f.v6)
		if err != nil {
			return nil, err
		}
		out = append(out, l...)
	}
	return out, nil
}

// LeaseView is a lease as the console shows it.
type LeaseView struct {
	svcstage.Lease
	Scope     string `json:"scope"`
	Interface string `json:"interface"`
	Active    bool   `json:"active"`
}

// DHCPLeases lists the leases of this node's DHCP servers, newest expiry
// first.
func (e *Engine) DHCPLeases(ctx context.Context) (any, error) {
	if e.conf.services == nil {
		return []LeaseView{}, nil
	}
	res := e.conf.services.Applied()
	if res == nil {
		return []LeaseView{}, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	leases, err := e.serviceLeases(ctx, res)
	if err != nil {
		return nil, err
	}
	scopes := map[string]svcrender.Scope{}
	for _, s := range res.Scopes {
		scopes[key(s.V6, s.SubnetID)] = s
	}
	now := time.Now()
	out := make([]LeaseView, 0, len(leases))
	for _, l := range leases {
		s := scopes[key(l.V6, l.SubnetID)]
		out = append(out, LeaseView{Lease: l, Scope: s.Name, Interface: s.Interface, Active: l.Active(now)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Expires.After(out[j].Expires) })
	return out, nil
}

func key(v6 bool, id uint32) string { return fmt.Sprintf("%v/%d", v6, id) }

// servicesRuntime reports which service daemons run and how many leases
// each scope holds. Nil when the node runs no service.
func (e *Engine) servicesRuntime() map[string]any {
	if e.conf.services == nil {
		return nil
	}
	res := e.conf.services.Applied()
	if res == nil || !res.Enabled() {
		return nil
	}
	daemons := map[string]string{}
	for _, d := range res.Daemons {
		daemons[d] = "unavailable"
		if e.netops != nil {
			if s, err := e.netops.DaemonState(d, svcRunDir); err == nil {
				daemons[d] = s
			}
		}
	}
	out := map[string]any{"daemons": daemons, "open": res.Open}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if leases, err := e.serviceLeases(ctx, res); err == nil {
		counts := map[string]int{}
		now := time.Now()
		for _, l := range leases {
			if l.Active(now) {
				counts[key(l.V6, l.SubnetID)]++
			}
		}
		var scopes []map[string]any
		for _, s := range res.Scopes {
			scopes = append(scopes, map[string]any{"name": s.Name, "interface": s.Interface, "subnet": s.Subnet, "leases": counts[key(s.V6, s.SubnetID)]})
		}
		out["scopes"] = scopes
	} else {
		out["leases_error"] = err.Error()
	}
	return out
}
