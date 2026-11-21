package engine

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/noahzmr/testudo/internal/config"
	"github.com/noahzmr/testudo/internal/events"
	"github.com/noahzmr/testudo/internal/fwrender"
	"github.com/noahzmr/testudo/internal/fwstage"
	"github.com/noahzmr/testudo/internal/health"
	"github.com/noahzmr/testudo/internal/model"
	"github.com/noahzmr/testudo/internal/netops"
)

// The packet filter is the model's: internal/fwrender renders it, the
// nftables stage (internal/fwstage) loads it in one transaction and checks
// every firewallReconcileInterval that the kernel still holds it, loading
// it again when not. Nothing else writes the table.

// firewallReconcileInterval is how often the kernel's table is compared with
// the model's ruleset. Drift is rare (a reboot, a stray nft flush), so a
// slow cadence is plenty; the boot apply is what matters most.
const firewallReconcileInterval = 30 * time.Second

// firewallPolicyPath is where the old firewall manager kept its policy; it
// is read once, to move it into the model.
func firewallPolicyPath(cfg config.Config) string {
	return filepath.Join(cfg.StorageDir, "firewall.json")
}

// fwUnprivilegedHint is the remediation for a packet filter the process may
// not read or write.
const fwUnprivilegedHint = "run with the privileged helper (the default) or grant CAP_NET_ADMIN"

// isPermissionError recognises the EPERM wording surfaced by nftables reads
// and writes from an unprivileged process.
func isPermissionError(msg string) bool {
	m := strings.ToLower(msg)
	return strings.Contains(m, "operation not permitted") || strings.Contains(m, "permission denied")
}

// firewallProtectedPorts returns the TCP ports the input chain always
// accepts: SSH and the console's port. Losing either is the one firewall
// mistake that cannot be fixed remotely.
func firewallProtectedPorts(cfg config.Config) []int {
	ports := []int{22}
	if _, p, err := net.SplitHostPort(strings.TrimSpace(cfg.WebListen)); err == nil {
		if n, err := strconv.Atoi(p); err == nil && n > 0 && n < 65536 && n != 22 {
			ports = append(ports, n)
		}
	}
	return ports
}

// unavailableRunner stands in for the privileged side when there is none:
// every change of the packet filter is refused with the reason.
type unavailableRunner struct{}

var errNoPacketFilter = errors.New("the packet filter cannot be changed here: no privileged helper (start with privileges, or --allow-netops-write)")

func (unavailableRunner) WritesAllowed() bool                         { return false }
func (unavailableRunner) NftCheck(string) error                       { return errNoPacketFilter }
func (unavailableRunner) NftApply(string) error                       { return errNoPacketFilter }
func (unavailableRunner) NftListTable(string, string) ([]byte, error) { return nil, errNoPacketFilter }

// newPacketFilter builds the nftables stage.
func newPacketFilter(cfg config.Config, nw *netops.Writer) *fwstage.Stage {
	st := &fwstage.Stage{Runner: unavailableRunner{}, ProtectedTCPPorts: firewallProtectedPorts(cfg)}
	if nw != nil {
		st.Runner = nw
	}
	return st
}

// PacketFilter returns the nftables stage.
func (e *Engine) PacketFilter() *fwstage.Stage { return e.fwNft }

// startFirewallReconciler keeps the kernel's table in step with the model.
// Transitions are surfaced as anomalies, so a foreign flush, a reload that
// fails or a drift that cannot be corrected (writes disabled) show up in
// Alerts and in the Health tab's "firewall" row.
func (e *Engine) startFirewallReconciler(ctx context.Context) {
	if e.netops == nil {
		e.MarkSubsystem("firewall", false, health.StateUnprivileged, "no privileged helper", fwUnprivilegedHint)
		return
	}
	e.MarkSubsystem("firewall", false, health.StateOK, "", "")
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		tick := time.NewTicker(firewallReconcileInterval)
		defer tick.Stop()
		prev := ""
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
			}
			d := e.fwNft.Reconcile()
			now := time.Now()
			state := "ok"
			if d.Error != "" {
				state = "error:" + d.Error
			}
			if d.Reloaded {
				e.bus.Publish(events.Event{Kind: events.KindAnomaly, Time: now, Source: "firewall",
					Payload: events.AnomalyPayload{Severity: string(events.SevWarn),
						Message: "the kernel's packet filter differed from the model's and was loaded again"}})
			}
			if state == prev {
				continue
			}
			switch {
			case d.Error != "" && isPermissionError(d.Error):
				e.MarkSubsystem("firewall", false, health.StateUnprivileged, d.Error, fwUnprivilegedHint)
			case d.Error != "":
				e.MarkSubsystem("firewall", false, health.StateDegraded, d.Error, "")
				e.bus.Publish(events.Event{Kind: events.KindAnomaly, Time: now, Source: "firewall",
					Payload: events.AnomalyPayload{Severity: string(events.SevError), Message: "packet filter: " + d.Error}})
			default:
				e.MarkSubsystem("firewall", false, health.StateOK, "", "")
				if strings.HasPrefix(prev, "error:") {
					e.bus.Publish(events.Event{Kind: events.KindAnomaly, Time: now, Source: "firewall",
						Payload: events.AnomalyPayload{Severity: string(events.SevInfo),
							Message: "packet filter back in step with the model"}})
				}
			}
			prev = state
		}
	}()
}

// FirewallView is the running packet filter as the UIs and the command line
// show it: whether the kernel holds the model's ruleset, and the model's
// rules with what each has matched. Rules are changed in the model.
type FirewallView struct {
	fwstage.Status
	Policy string     `json:"policy,omitempty"`
	Rules  []RuleView `json:"rules"`
	NAT    []RuleView `json:"nat"`
}

// RuleView is one filter or NAT rule of the model.
type RuleView struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Enabled   bool   `json:"enabled"`
	Direction string `json:"direction"` // in, out, forward; dnat, snat, masquerade, one_to_one
	Action    string `json:"action"`
	Match     string `json:"match"`
	Owner     string `json:"owner,omitempty"`
	Packets   uint64 `json:"packets"`
	Bytes     uint64 `json:"bytes"`
}

// FirewallView reads the model and the kernel's counters.
func (e *Engine) FirewallView() FirewallView {
	var v FirewallView
	if e.fwNft != nil {
		v.Status = e.fwNft.Status()
	}
	if e.conf.store == nil {
		return v
	}
	st := e.conf.store.Current()
	site, node := e.locate(st)
	counters := map[string]fwstage.Counter{}
	if e.fwNft != nil {
		if c, err := e.fwNft.Counters(); err == nil {
			counters = c
		}
	}
	if p := fwrender.Policy(st, fwrender.Options{SiteID: site, NodeID: node}); p != nil {
		v.Policy = p.Name
	}
	zone := func(r model.Ref[model.Zone]) string {
		if o, ok := st.Get(model.KindZone, r.ID); ok {
			return o.GetMeta().Name
		}
		return ""
	}
	alias := func(refs []model.Ref[model.Alias], nets []string) string {
		var out []string
		for _, r := range refs {
			if o, ok := st.Get(model.KindAlias, r.ID); ok {
				out = append(out, o.GetMeta().Name)
			}
		}
		return strings.Join(append(out, nets...), ",")
	}
	applies := func(o model.Entity) (model.Entity, bool) {
		if !model.AppliesTo(o, site, node) {
			return nil, false
		}
		eff, _, err := model.Effective(o, site, node)
		return eff, err == nil
	}
	for _, o := range st.List(model.KindFilterRule) {
		eff, ok := applies(o)
		if !ok {
			continue
		}
		r := eff.(*model.FilterRule)
		var m []string
		if z := zone(r.SourceZone); z != "" {
			m = append(m, "from "+z)
		}
		if s := alias(r.Source, r.SourceNets); s != "" {
			m = append(m, "src "+s)
		}
		if z := zone(r.DestinationZone); z != "" {
			m = append(m, "to "+z)
		}
		if d := alias(r.Destination, r.DestinationNets); d != "" {
			m = append(m, "dst "+d)
		}
		if r.Protocol != "any" {
			m = append(m, r.Protocol)
		}
		if p := alias(r.PortAliases, r.Ports); p != "" {
			m = append(m, "port "+p)
		}
		if len(r.States) > 0 {
			m = append(m, "ct "+strings.Join(r.States, ","))
		}
		c := counters[r.ID]
		v.Rules = append(v.Rules, RuleView{ID: r.ID, Name: r.Name, Enabled: r.Enabled, Direction: r.Direction, Action: r.Action,
			Match: strings.Join(m, " "), Owner: r.Owner, Packets: c.Packets, Bytes: c.Bytes})
	}
	sort.SliceStable(v.Rules, func(i, j int) bool { return v.Rules[i].Name < v.Rules[j].Name })
	for _, o := range st.List(model.KindNATRule) {
		eff, ok := applies(o)
		if !ok {
			continue
		}
		r := eff.(*model.NATRule)
		var m []string
		if z := zone(r.Zone); z != "" {
			m = append(m, "on "+z)
		}
		if r.Protocol != "any" {
			m = append(m, r.Protocol)
		}
		if len(r.SourceNets) > 0 {
			m = append(m, "src "+strings.Join(r.SourceNets, ","))
		}
		if r.Destination != "" || r.Port != "" {
			m = append(m, strings.Trim(r.Destination+":"+r.Port, ":"))
		}
		if r.TranslateTo != "" {
			m = append(m, "-> "+strings.Trim(r.TranslateTo+":"+r.TranslatePort, ":"))
		}
		c := counters[r.ID]
		v.NAT = append(v.NAT, RuleView{ID: r.ID, Name: r.Name, Enabled: r.Enabled, Direction: r.Type, Action: r.Type,
			Match: strings.Join(m, " "), Packets: c.Packets, Bytes: c.Bytes})
	}
	sort.SliceStable(v.NAT, func(i, j int) bool { return v.NAT[i].Name < v.NAT[j].Name })
	return v
}

// RenderedFirewall is the ruleset the model renders for this node, as nft
// would load it.
func (e *Engine) RenderedFirewall() (string, error) {
	if e.conf.store == nil {
		return "", errors.New("the configuration model is unavailable")
	}
	st := e.conf.store.Current()
	site, node := e.locate(st)
	out, err := fwrender.Render(st, fwrender.Options{SiteID: site, NodeID: node, ProtectedTCPPorts: firewallProtectedPorts(e.cfg)})
	return string(out), err
}

// AuditFirewall records a firewall operation to the audit log.
func (e *Engine) AuditFirewall(actor, op, args string, opErr error) {
	e.auditOp(context.Background(), actor, "fw_"+op, args, opErr)
}

// Audit records any engine-level security-relevant event (logins, user and
// settings changes) with the human actor. Args is a JSON summary and must
// never carry secret material.
func (e *Engine) Audit(actor, op, args string, opErr error) {
	e.auditOp(context.Background(), actor, op, args, opErr)
}
