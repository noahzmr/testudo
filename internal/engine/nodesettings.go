package engine

import (
	"context"
	"encoding/json"
	"log"
	"time"

	"github.com/noahzmr/testudo/internal/config"
	"github.com/noahzmr/testudo/internal/confstore"
	sentryx "github.com/noahzmr/testudo/internal/integrations/sentry"
	"github.com/noahzmr/testudo/internal/model"
)

// A node's thresholds and integrations are model objects (node_settings):
// the object with the narrowest scope that applies to the node is used,
// and each change of the model is carried into the running settings.
// settings.json keeps what stays the node's own (whether it may write
// to the kernel) and a copy of the rest. A settings.json from before is
// moved into the model once.

var scopeRank = map[string]int{"global": 1, "site": 2, "node": 3}

// nodeSettings returns the node settings that apply to this node, or nil.
func nodeSettings(st *confstore.State, site, node string) *model.NodeSettings {
	var best *model.NodeSettings
	for _, o := range st.List(model.KindNodeSettings) {
		if !model.AppliesTo(o, site, node) {
			continue
		}
		eff, _, err := model.Effective(o, site, node)
		if err != nil {
			continue
		}
		ns := eff.(*model.NodeSettings)
		if best == nil || scopeRank[ns.Scope.Level()] > scopeRank[best.Scope.Level()] {
			best = ns
		}
	}
	return best
}

// fromModel writes the model's settings into t: an empty value is the
// built-in default. What stays the node's own is left as it is.
func fromModel(t *config.Thresholds, ns *model.NodeSettings) {
	d := config.DefaultThresholds()
	f := func(v, def float64) float64 {
		if v > 0 {
			return v
		}
		return def
	}
	t.PacketLossPct = f(ns.PacketLossPct, d.PacketLossPct)
	t.DNSLatencyMs = f(ns.DNSLatencyMs, d.DNSLatencyMs)
	t.JitterMs = f(ns.JitterMs, d.JitterMs)
	t.RTTMs = f(ns.RTTMs, d.RTTMs)
	t.RetransmissionsPct = f(ns.RetransmissionsPct, d.RetransmissionsPct)
	t.FlowRetransPct = f(ns.FlowRetransPct, d.FlowRetransPct)
	t.ExpectedDownMbps, t.ExpectedUpMbps = ns.ExpectedDownMbps, ns.ExpectedUpMbps
	t.IncidentCooldown = d.IncidentCooldown
	if c, err := time.ParseDuration(ns.IncidentCooldown); err == nil && c > 0 {
		t.IncidentCooldown = c
	}
	t.IPFIXEnabled, t.IPFIXEndpoint, t.IPFIXDomainID = ns.IPFIXEnabled, ns.IPFIXEndpoint, ns.IPFIXDomainID
	t.IPFIXIntervalSec = d.IPFIXIntervalSec
	if ns.IPFIXIntervalSec > 0 {
		t.IPFIXIntervalSec = ns.IPFIXIntervalSec
	}
	t.EBPFEnabled = ns.EBPFEnabled
	t.SentryDSN = ns.SentryDSN
	t.GuacamoleURL, t.GuacamoleConnID, t.GuacamoleTemplate = ns.GuacamoleURL, ns.GuacamoleConnID, ns.GuacamoleTemplate
	t.GuacamoleAPIUser, t.GuacamoleAPIPassword = ns.GuacamoleAPIUser, ns.GuacamoleAPIPassword
	t.GuacamoleRecordingPath, t.GuacamoleTypescriptPath = ns.GuacamoleRecordingPath, ns.GuacamoleTypescriptPath
	t.MaxMindEnabled, t.MaxMindDBDir, t.MaxMindAccountID = ns.MaxMindEnabled, ns.MaxMindDBDir, ns.MaxMindAccountID
	t.MaxMindLicenseKey, t.MaxMindEditions = ns.MaxMindLicenseKey, ns.MaxMindEditions
	t.MaxMindAutoUpdate, t.MaxMindRefreshHours = ns.MaxMindAutoUpdate, ns.MaxMindRefreshHours
}

// toModel is the model object for the settings t, with only what differs
// from the built-in defaults set.
func toModel(t config.Thresholds) *model.NodeSettings {
	d := config.DefaultThresholds()
	f := func(v, def float64) float64 {
		if v == def {
			return 0
		}
		return v
	}
	ns := &model.NodeSettings{
		PacketLossPct: f(t.PacketLossPct, d.PacketLossPct), DNSLatencyMs: f(t.DNSLatencyMs, d.DNSLatencyMs),
		JitterMs: f(t.JitterMs, d.JitterMs), RTTMs: f(t.RTTMs, d.RTTMs),
		RetransmissionsPct: f(t.RetransmissionsPct, d.RetransmissionsPct), FlowRetransPct: f(t.FlowRetransPct, d.FlowRetransPct),
		ExpectedDownMbps: t.ExpectedDownMbps, ExpectedUpMbps: t.ExpectedUpMbps,
		IPFIXEnabled: t.IPFIXEnabled, IPFIXEndpoint: t.IPFIXEndpoint, IPFIXDomainID: t.IPFIXDomainID,
		EBPFEnabled: t.EBPFEnabled, SentryDSN: t.SentryDSN,
		GuacamoleURL: t.GuacamoleURL, GuacamoleConnID: t.GuacamoleConnID, GuacamoleTemplate: t.GuacamoleTemplate,
		GuacamoleAPIUser: t.GuacamoleAPIUser, GuacamoleAPIPassword: t.GuacamoleAPIPassword,
		GuacamoleRecordingPath: t.GuacamoleRecordingPath, GuacamoleTypescriptPath: t.GuacamoleTypescriptPath,
		MaxMindEnabled: t.MaxMindEnabled, MaxMindDBDir: t.MaxMindDBDir, MaxMindAccountID: t.MaxMindAccountID,
		MaxMindLicenseKey: t.MaxMindLicenseKey, MaxMindEditions: t.MaxMindEditions,
		MaxMindAutoUpdate: t.MaxMindAutoUpdate, MaxMindRefreshHours: t.MaxMindRefreshHours,
	}
	if t.IncidentCooldown != d.IncidentCooldown && t.IncidentCooldown > 0 {
		ns.IncidentCooldown = t.IncidentCooldown.String()
	}
	if t.IPFIXIntervalSec != d.IPFIXIntervalSec {
		ns.IPFIXIntervalSec = t.IPFIXIntervalSec
	}
	return ns
}

// migrateSettings moves the thresholds and integrations of settings.json
// into the model when nothing there applies to this node yet: as the
// global settings on the first node, as this node's own when another
// member's are already global and this node's differ.
func (e *Engine) migrateSettings(ctx context.Context) {
	st := e.conf.store.Current()
	site, node := e.locate(st)
	if nodeSettings(st, site, node) != nil {
		return
	}
	ns := toModel(e.settings.Snapshot())
	any := len(st.List(model.KindNodeSettings)) > 0
	empty, _ := json.Marshal(&model.NodeSettings{})
	own, _ := json.Marshal(ns)
	if any && string(own) == string(empty) {
		return
	}
	ns.Meta = model.Meta{ID: confstore.NewID(), Name: "settings", Description: "Moved from settings.json"}
	if any {
		if node == "" {
			return
		}
		ns.Name = "settings-" + safeObjName(e.cfg.NodeName)
		if e.cfg.NodeName == "" {
			ns.Name = "settings-" + node[:8]
		}
		ns.Scope = model.NodeScope(node)
	}
	raw, _ := json.Marshal(ns)
	op := confstore.Op{Type: confstore.OpCreate, Kind: model.KindNodeSettings, ID: ns.ID, Object: raw}
	if err := e.systemChange(ctx, "settings.json moved into the model", []confstore.Op{op}); err != nil {
		log.Printf("settings: moving settings.json into the model: %v (tried again at the next start)", err)
		return
	}
	log.Printf("settings: thresholds and integrations moved into the model as %q", ns.Name)
}

// syncSettings carries the model's settings for this node into the running
// settings, and follows every change of the model.
func (e *Engine) syncSettings(ctx context.Context) {
	apply := func() {
		st := e.conf.store.Current()
		site, node := e.locate(st)
		ns := nodeSettings(st, site, node)
		if ns == nil {
			return
		}
		before := e.settings.Snapshot()
		next := before
		fromModel(&next, ns)
		if next == before {
			return
		}
		if err := e.settings.Update(func(t *config.Thresholds) { *t = next }); err != nil {
			log.Printf("settings: %v", err)
		}
		if next.SentryDSN != before.SentryDSN {
			_ = sentryx.Init(next.SentryDSN, "testudo")
		}
	}
	apply()
	events, cancel := e.conf.store.Subscribe(16)
	go func() {
		defer cancel()
		for {
			select {
			case <-ctx.Done():
				return
			case ev := <-events:
				for _, c := range ev.Changes {
					if c.Kind == model.KindNodeSettings || c.Kind == model.KindClusterNode {
						apply()
						break
					}
				}
				if ev.Resync {
					apply()
				}
			}
		}
	}()
}
