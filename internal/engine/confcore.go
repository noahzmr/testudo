package engine

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/noahzmr/testudo/internal/aliasfeed"
	"github.com/noahzmr/testudo/internal/confapply"
	"github.com/noahzmr/testudo/internal/config"
	"github.com/noahzmr/testudo/internal/confstore"
	"github.com/noahzmr/testudo/internal/fwbridge"
	"github.com/noahzmr/testudo/internal/model"
	"github.com/noahzmr/testudo/internal/storage"
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
}

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
	var stage confapply.Stage
	if e.fwNft != nil {
		e.fwNft.Locate, e.fwNft.Elements = localNode, c.feed.Snapshot
		stage = e.fwNft
	} else {
		// A typed nil must not reach the interface, hence the explicit check.
		var fw fwbridge.Manager
		if e.fw != nil {
			fw = e.fw
		}
		stage = &fwbridge.Stage{Manager: fw, Locate: localNode}
	}
	c.apply, c.err = confapply.New(c.store, confapply.Options{Dir: dir, Notify: e.configNotice}, stage)
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
	args, _ := json.Marshal(map[string]any{"record": n.Index, "reason": n.Reason})
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
	}
	if e.fwNft != nil {
		go e.aliasFeedLoop(ctx)
	}
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
	return out
}

// localNode finds this machine in the model by host name. Until a node is
// defined, only objects with global scope apply here.
func localNode(st *confstore.State) (siteID, nodeID string) {
	host, err := os.Hostname()
	if err != nil {
		return "", ""
	}
	host = strings.ToLower(host)
	for _, e := range st.List(model.KindClusterNode) {
		n := e.(*model.ClusterNode)
		if strings.ToLower(n.Hostname) == host || strings.ToLower(n.Name) == host {
			return n.Site.ID, n.ID
		}
	}
	return "", ""
}
