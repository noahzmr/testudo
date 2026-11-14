package engine

import (
	"context"
	"log"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/noahzmr/testudo/internal/config"
	"github.com/noahzmr/testudo/internal/events"
	"github.com/noahzmr/testudo/internal/firewall"
	"github.com/noahzmr/testudo/internal/fwstage"
	"github.com/noahzmr/testudo/internal/health"
	"github.com/noahzmr/testudo/internal/netops"
)

// firewallReconcileInterval is how often the live nftables tables are compared
// with the policy file. Drift is rare (a reboot, a stray `nft flush ruleset`),
// so a slow cadence is plenty; the boot apply is what matters most.
const firewallReconcileInterval = 30 * time.Second

// firewallPolicyPath is the desired-state file next to settings.json.
func firewallPolicyPath(cfg config.Config) string {
	return filepath.Join(cfg.StorageDir, "firewall.json")
}

// fwUnprivilegedHint mirrors the WireGuard row's remediation: reading and
// writing nftables needs CAP_NET_ADMIN, which the privileged helper normally
// holds on the engine's behalf.
const fwUnprivilegedHint = "grant CAP_NET_ADMIN (sudo setcap cap_net_admin+ep ./testudo) or run with the privileged helper"

// fwCond is the firewall reconciler's condition, derived from a Status.
type fwCond int

const (
	fwCondOK          fwCond = iota
	fwCondUnreadable         // kernel tables could not be read (DriftError)
	fwCondApplyFailed        // the last apply returned an error
	fwCondDrift              // tables readable but not matching the policy
)

func firewallCondition(st firewall.Status) fwCond {
	switch {
	case st.DriftError != "":
		return fwCondUnreadable
	case st.LastError != "":
		return fwCondApplyFailed
	case !st.InSync:
		return fwCondDrift
	}
	return fwCondOK
}

// isPermissionError recognises the netlink/EPERM wording surfaced by nftables
// reads and writes from an unprivileged process.
func isPermissionError(msg string) bool {
	m := strings.ToLower(msg)
	return strings.Contains(m, "operation not permitted") || strings.Contains(m, "permission denied")
}

// firewallProtectedPorts returns the TCP ports the baseline must always accept
// on input when enforcing: SSH and the Web UI listen port. Losing either is
// the one firewall mistake that cannot be fixed remotely.
func firewallProtectedPorts(cfg config.Config) []uint16 {
	ports := []uint16{22}
	if _, p, err := net.SplitHostPort(strings.TrimSpace(cfg.WebListen)); err == nil {
		if n, err := strconv.Atoi(p); err == nil && n > 0 && n < 65536 {
			ports = append(ports, uint16(n))
		}
	}
	return ports
}

// openFirewall builds the policy manager over the netops writer. A policy file
// that fails to load is a hard problem (the operator's intent is unreadable),
// but not one that should stop the observability engine: it is logged, the
// firewall subsystem is marked failed, and all firewall mutations are refused
// until the file is fixed.
func openFirewall(cfg config.Config, nw *netops.Writer) (*firewall.Manager, *fwstage.Stage, error) {
	if nw == nil {
		return nil, nil, nil
	}
	opts := firewall.Options{Path: firewallPolicyPath(cfg), ProtectedTCPPorts: firewallProtectedPorts(cfg)}
	// With nft available on the privileged side, the manager hands its
	// tables to the nftables stage, which loads them together with the
	// model's rules as one ruleset. Otherwise it programs the kernel over
	// netlink as before and the model is enforced through the bridge.
	if nw.NftAvailable() {
		stage := &fwstage.Stage{Runner: nw}
		m, err := firewall.Open(opts, stage)
		if err != nil {
			return nil, nil, err
		}
		stage.SetManager(m)
		return m, stage, nil
	}
	m, err := firewall.Open(opts, nw)
	return m, nil, err
}

// Firewall returns the policy manager (nil when netops is unavailable or the
// policy file failed to load; see FirewallError).
func (e *Engine) Firewall() *firewall.Manager { return e.fw }

// FirewallError is the reason the firewall manager is unavailable, or nil.
func (e *Engine) FirewallError() error { return e.fwErr }

// startFirewallReconciler applies the policy at boot and keeps the kernel in
// sync with it. Transitions are surfaced as anomalies so a foreign flush, a
// failed boot apply or a drift that cannot be corrected (writes disabled) all
// show up in Alerts and in the Health tab's "firewall" row.
func (e *Engine) startFirewallReconciler(ctx context.Context) {
	if e.fw == nil {
		if e.fwErr != nil {
			e.MarkSubsystem("firewall", false, health.StateFailed, e.fwErr.Error(),
				"fix or remove the policy file and restart")
		}
		return
	}
	e.MarkSubsystem("firewall", false, health.StateOK, "", "")
	if n := e.fw.Imported(); n > 0 {
		log.Printf("firewall: imported %d pre-policy kernel entries into %s", n, firewallPolicyPath(e.cfg))
	}

	// The reconciler reports after every check; only transitions between
	// conditions reach the health registry and the alert stream, so an
	// unprivileged box does not emit an alert every 30 s.
	prev := fwCondOK
	e.fw.SetOnChange(func(st firewall.Status) {
		cond := firewallCondition(st)
		if cond == prev {
			return
		}
		now := time.Now()
		switch cond {
		case fwCondUnreadable:
			// Not a drift: the kernel state could not be read at all. Report it
			// as the privilege posture it is, like the WireGuard row does.
			msg := "kernel tables unreadable: " + st.DriftError
			if isPermissionError(st.DriftError) {
				e.MarkSubsystem("firewall", false, health.StateUnprivileged, msg, fwUnprivilegedHint)
			} else {
				e.MarkSubsystem("firewall", false, health.StateDegraded, msg, "")
			}
		case fwCondApplyFailed:
			e.MarkSubsystem("firewall", false, health.StateDegraded, st.LastError, "")
			e.bus.Publish(events.Event{Kind: events.KindAnomaly, Time: now, Source: "firewall",
				Payload: events.AnomalyPayload{Severity: string(events.SevError),
					Message: "firewall policy apply failed: " + st.LastError}})
		case fwCondDrift:
			detail := strings.Join(st.DriftDetail, "; ")
			hint := "enable netops writes so the reconciler can re-apply the policy"
			if st.WritesAllowed {
				hint = "re-apply will be retried on the next reconcile tick"
			}
			e.MarkSubsystem("firewall", false, health.StateDegraded, "kernel tables drifted from policy: "+detail, hint)
			e.bus.Publish(events.Event{Kind: events.KindAnomaly, Time: now, Source: "firewall",
				Payload: events.AnomalyPayload{Severity: string(events.SevWarn),
					Message: "firewall drift detected (" + detail + ")"}})
		case fwCondOK:
			e.MarkSubsystem("firewall", false, health.StateOK, "", "")
			if prev == fwCondDrift || prev == fwCondApplyFailed {
				e.bus.Publish(events.Event{Kind: events.KindAnomaly, Time: now, Source: "firewall",
					Payload: events.AnomalyPayload{Severity: string(events.SevInfo),
						Message: "firewall policy re-applied; kernel tables back in sync"}})
			}
		}
		prev = cond
	})

	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		e.fw.Run(ctx, firewallReconcileInterval)
	}()
}

// AuditFirewall records a firewall policy mutation to the audit log. Args
// never contain anything secret - rules are public configuration. The UIs
// call it after driving the manager so every policy change is traceable next
// to the netlink mutations the helper logs.
func (e *Engine) AuditFirewall(actor, op, args string, opErr error) {
	e.auditOp(context.Background(), actor, "fw_"+op, args, opErr)
}

// Audit records any engine-level security-relevant event (logins, user and
// settings changes) with the human actor. Args is a JSON summary and must
// never carry secret material.
func (e *Engine) Audit(actor, op, args string, opErr error) {
	e.auditOp(context.Background(), actor, op, args, opErr)
}
