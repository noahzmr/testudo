package engine

import (
	"context"
	"errors"
	"fmt"
	"log"
	"path/filepath"
	"strings"
	"time"

	"github.com/noahzmr/testudo/internal/capture"
	"github.com/noahzmr/testudo/internal/events"
	"github.com/noahzmr/testudo/internal/integrations/guacamole"
	"github.com/noahzmr/testudo/internal/pam"
	"github.com/noahzmr/testudo/internal/sshca"
	"github.com/noahzmr/testudo/internal/storage"
)

// pamTickInterval is how often active grants are checked for expiry and
// sampled for observed flows.
const pamTickInterval = 10 * time.Second

// pamCapturer records a grant's traffic with the tcpdump manager (one rolling
// 64 MiB file per grant, no fixed duration - the grant's end stops it).
type pamCapturer struct{ m *capture.TCPDumpManager }

func (c pamCapturer) Start(name, iface, bpf string) (string, error) {
	job, err := c.m.Start(iface, name, bpf, 64, 0)
	if err != nil {
		return "", err
	}
	return job.ID, nil
}

func (c pamCapturer) Stop(id string) error { return c.m.Stop(id) }

// pamPeers resolves a user to the tunnel addresses of the WireGuard peers
// bound to them (wg_peer_meta.user). Live AllowedIPs come from the collector
// snapshot, falling back to a direct netops read.
type pamPeers struct{ e *Engine }

func (p pamPeers) PeerIPs(ctx context.Context, user string) ([]string, error) {
	if p.e.store == nil {
		return nil, nil
	}
	bound, err := p.e.store.WGPeerUsers(ctx)
	if err != nil {
		return nil, err
	}
	mine := map[string]bool{}
	for pub, u := range bound {
		if u == user {
			mine[pub] = true
		}
	}
	if len(mine) == 0 {
		return nil, nil
	}
	seen := map[string]bool{}
	var out []string
	add := func(pub string, ips []string) {
		if !mine[pub] {
			return
		}
		for _, ip := range ips {
			if !seen[ip] {
				seen[ip] = true
				out = append(out, ip)
			}
		}
	}
	if p.e.wg0 != nil {
		if snap, ok := p.e.wg0.Snapshot(); ok {
			for _, d := range snap.Devices {
				for _, peer := range d.Peers {
					add(peer.PublicKey, peer.AllowedIPs)
				}
			}
		}
	}
	if len(out) == 0 && p.e.netops != nil {
		if devs, err := p.e.netops.ListWGDevices(); err == nil {
			for _, d := range devs {
				for _, peer := range d.Peers {
					add(peer.PublicKey, peer.AllowedIPs)
				}
			}
		}
	}
	return out, nil
}

// startPAM wires the privileged-access manager over the firewall manager
// (enforcement), netops (conntrack kill), tcpdump (per-grant capture) and the
// WireGuard peer bindings, then runs its expiry loop. It is skipped - with a
// log line - when any of storage, netops or the firewall policy is missing.
func (e *Engine) startPAM(ctx context.Context) {
	if e.store == nil || e.netops == nil || e.fw == nil {
		log.Printf("pam: disabled (needs storage, netops and the firewall policy)")
		return
	}
	var capturer pam.Capturer
	if td := e.TCPDump(); td != nil && capture.TCPDumpAvailable() {
		capturer = pamCapturer{m: td}
	}
	th := e.settings.Snapshot()
	e.pam = pam.New(e.store, e.fw, e.netops, capturer, pamPeers{e}, pam.Options{
		Device:  firstNonEmpty(th.WireGuardDevice, "wg0"),
		Broker:  e.guacBroker(),
		OnEvent: e.publishAccessEvent,
	})
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		e.pam.Run(ctx, pamTickInterval)
	}()
}

// PAM returns the privileged-access manager (nil when disabled).
func (e *Engine) PAM() *pam.Manager { return e.pam }

// guacBroker adapts the Guacamole REST broker to the PAM Broker surface. It
// reads the API credentials from settings on every call, so configuring
// Guacamole in the Settings tab takes effect without a restart; brokering is
// simply off while the credentials are blank.
type guacBroker struct{ e *Engine }

func (e *Engine) guacBroker() pam.Broker { return guacBroker{e} }

func (b guacBroker) broker() *guacamole.Broker {
	th := b.e.settings.Snapshot()
	if th.GuacamoleURL == "" || th.GuacamoleAPIUser == "" || th.GuacamoleAPIPassword == "" {
		return nil
	}
	return &guacamole.Broker{
		Client:         &guacamole.Client{BaseURL: th.GuacamoleURL, Username: th.GuacamoleAPIUser, Password: th.GuacamoleAPIPassword},
		RecordingPath:  th.GuacamoleRecordingPath,
		TypescriptPath: th.GuacamoleTypescriptPath,
	}
}

func (b guacBroker) Activate(ctx context.Context, g storage.PAMGrant, res storage.PAMResource) (string, error) {
	br := b.broker()
	if br == nil {
		return "", guacamole.ErrNotConfigured
	}
	host := res.CIDR
	if i := strings.IndexByte(host, '/'); i >= 0 {
		host = host[:i]
	}
	return br.Activate(ctx, guacamole.Request{
		GrantID: g.ID, User: g.User, Kind: res.Kind, Host: host, Port: res.PortLo,
		Login: res.Login, TemplateID: res.BrokerRef,
	})
}

func (b guacBroker) Deactivate(ctx context.Context, ref string) error {
	br := b.broker()
	if br == nil {
		return nil
	}
	return br.Deactivate(ctx, ref)
}

func (b guacBroker) LaunchURL(ref string) string {
	br := b.broker()
	if br == nil {
		return ""
	}
	return br.LaunchURL(ref)
}

// SSHCA returns the SSH user certificate authority, opening (and on first use
// generating) it under <storage>/sshca. nil with an error when unavailable.
func (e *Engine) SSHCA() (*sshca.CA, error) {
	e.sshcaMu.Lock()
	defer e.sshcaMu.Unlock()
	if e.sshca != nil {
		return e.sshca, nil
	}
	ca, err := sshca.Open(filepath.Join(e.cfg.StorageDir, "sshca"))
	if err != nil {
		return nil, err
	}
	e.sshca = ca
	return ca, nil
}

// IssueSSHCert signs userPubKey for an active ssh grant of the requester:
// principal = the resource's login (or the user name), validity = the grant
// window, source-address = the grant's peer addresses. Audited.
func (e *Engine) IssueSSHCert(ctx context.Context, actor string, grantID, userPubKey string) (string, []string, error) {
	if e.pam == nil || e.store == nil {
		return "", nil, errors.New("privileged access unavailable")
	}
	g, err := e.store.GetPAMGrant(ctx, grantID)
	if err != nil {
		return "", nil, err
	}
	if g.User != actor {
		return "", nil, fmt.Errorf("grant %s belongs to %s", grantID, g.User)
	}
	if g.State != pam.StateActive {
		return "", nil, fmt.Errorf("grant is %s, not active", g.State)
	}
	res, err := e.store.GetPAMResource(ctx, g.ResourceID)
	if err != nil {
		return "", nil, err
	}
	if res.Kind != pam.KindSSH {
		return "", nil, fmt.Errorf("resource %s is %s, not ssh", res.Name, res.Kind)
	}
	ca, err := e.SSHCA()
	if err != nil {
		return "", nil, err
	}
	principal := firstNonEmpty(res.Login, g.User)
	cert, err := ca.Sign(sshca.Request{
		UserPublicKey: userPubKey, KeyID: g.ID + " " + g.User + " " + res.Name,
		Principals: []string{principal}, ValidAfter: g.StartsAt, ValidBefore: g.EndsAt, SourceAddrs: g.PeerIPs,
	})
	e.auditOp(ctx, actor, "pam_ssh_cert", fmt.Sprintf(`{"grant":%q,"resource":%q,"principal":%q}`, g.ID, res.Name, principal), err)
	if err != nil {
		return "", nil, err
	}
	return cert, []string{principal}, nil
}

// publishAccessEvent surfaces access events in Alerts: the emergency and
// failure paths as WARN, the ordinary lifecycle as INFO.
func (e *Engine) publishAccessEvent(ev storage.AccessEvent) {
	sev := events.SevInfo
	switch ev.Action {
	case "break_glass", "denied", "activation_failed", "capture_failed":
		sev = events.SevWarn
	case "resource_upsert", "resource_delete", "policy_upsert", "policy_delete", "peer_bind":
		// Configuration changes are in the access log; no alert noise.
		return
	}
	msg := fmt.Sprintf("access: %s %s", ev.Actor, ev.Action)
	if ev.GrantID != "" {
		msg += " " + ev.GrantID
	}
	if ev.Detail != "" {
		msg += " - " + ev.Detail
	}
	e.bus.Publish(events.Event{
		Kind: events.KindAnomaly, Time: ev.TS, Source: "pam",
		Payload: events.AnomalyPayload{Severity: string(sev), Message: msg},
	})
}
