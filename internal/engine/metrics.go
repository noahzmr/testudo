package engine

import (
	"errors"
	"time"

	"github.com/noahzmr/testudo/internal/health"
	"github.com/noahzmr/testudo/internal/model"
	"github.com/noahzmr/testudo/internal/promtext"
)

// Metrics is the node's state for a Prometheus scrape: subsystems,
// configuration, cluster, gateways, fabric paths, HA, load-balancer
// backends, packet-filter counters, WireGuard and flows. Everything comes
// from state the engine already keeps; a scrape runs no probe.
func (e *Engine) Metrics() []promtext.Sample {
	g, c := promtext.Gauge, promtext.Counter
	b := promtext.Bool
	out := []promtext.Sample{g("testudo_build_info", "The running build.", 1, "build", buildID())}
	for _, s := range e.Health() {
		out = append(out,
			g("testudo_subsystem_ok", "Whether a subsystem works (1) or is degraded, failed or unprivileged (0).", b(s.State == health.StateOK), "subsystem", s.Name),
			c("testudo_subsystem_restarts_total", "Restarts of a subsystem since the start.", float64(s.Restarts), "subsystem", s.Name))
	}
	out = append(out, g("testudo_config_ready", "Whether the configuration model is open and applied.", b(e.Ready() == nil)))
	if st := e.conf.store; st != nil {
		cur := st.Current()
		out = append(out, g("testudo_config_model_index", "Index of the newest record of the configuration model.", float64(cur.Index())))
		if e.conf.apply != nil {
			_, pending := e.conf.apply.Pending()
			out = append(out, g("testudo_config_pending", "Whether an applied change waits for confirmation.", b(pending)))
		}
		if e.conf.gateways != nil {
			for id, s := range e.conf.gateways.Status() {
				name := id
				if obj, ok := cur.Get(model.KindGateway, id); ok {
					name = obj.GetMeta().Name
				}
				out = append(out, g("testudo_gateway_up", "Whether a monitored gateway answers.", b(!s.Down), "gateway", name))
			}
		}
		if h := e.haRuntime(); h != nil {
			if role, ok := h["role"].(string); ok {
				out = append(out, g("testudo_ha_active", "Whether this node holds its HA pair's virtual addresses.", b(role == "active"), "pair", h["pair"].(string)))
			}
			if ds, ok := h["daemons"].(map[string]string); ok {
				for d, s := range ds {
					out = append(out, g("testudo_ha_daemon_up", "Whether an HA daemon runs.", b(s == "running"), "daemon", d))
				}
			}
		}
	}
	if mgr := e.cluster.mgr; mgr != nil {
		node := mgr.Node()
		out = append(out, g("testudo_cluster_member", "Whether this node belongs to a cluster.", b(node != nil)))
		if node != nil {
			leader, _ := node.Leader()
			out = append(out,
				g("testudo_cluster_leader", "Whether this node leads the cluster.", b(node.IsLeader())),
				g("testudo_cluster_quorum", "Whether this node knows a leader, so changes are possible.", b(leader != "")))
			if servers, err := node.Servers(); err == nil {
				voters := 0
				for _, s := range servers {
					if s.Voter {
						voters++
					}
				}
				out = append(out, g("testudo_cluster_members", "Members of the consensus group.", float64(len(servers))),
					g("testudo_cluster_voters", "Voting members of the consensus group.", float64(voters)))
			}
			for id, d := range node.Unreachable() {
				out = append(out, g("testudo_cluster_unreachable_seconds", "How long the leader has not reached a member.", d.Seconds(), "member", id))
			}
		}
	}
	if e.fabric.paths != nil {
		for _, p := range e.fabric.paths.Status() {
			l := []string{"device", p.Device, "peer", p.PeerNode, "color", p.Color}
			out = append(out,
				g("testudo_fabric_path_up", "Whether a fabric tunnel carries traffic.", b(!p.Down), l...),
				g("testudo_fabric_path_latency_seconds", "Measured latency of a fabric tunnel.", p.LatencyMs/1000, l...),
				g("testudo_fabric_path_jitter_seconds", "Measured jitter of a fabric tunnel.", p.JitterMs/1000, l...),
				g("testudo_fabric_path_loss_ratio", "Share of lost probes over the window.", p.Loss, l...))
		}
	}
	if e.conf.backends != nil {
		for addr, s := range e.conf.backends.Status() {
			out = append(out, g("testudo_lb_backend_up", "Whether a load-balancer backend passes its health check.", b(!s.Down), "backend", addr))
		}
	}
	if e.fwNft != nil {
		if cs, err := e.fwNft.Counters(); err == nil {
			for rule, k := range cs {
				out = append(out,
					c("testudo_firewall_rule_packets_total", "Packets a rule of the model matched.", float64(k.Packets), "rule", rule),
					c("testudo_firewall_rule_bytes_total", "Bytes a rule of the model matched.", float64(k.Bytes), "rule", rule))
			}
		}
	}
	if s, ok := e.WireGuardSummary(); ok {
		out = append(out, g("testudo_wireguard_peers", "WireGuard peers on this node.", float64(s.Peers)),
			g("testudo_wireguard_peers_healthy", "WireGuard peers with a recent handshake.", float64(s.HealthyPeers)))
	}
	if e.flowAgg != nil {
		out = append(out, g("testudo_flows_active", "Flows in the live flow table.", float64(len(e.flowAgg.Snapshot()))))
	}
	out = append(out, g("testudo_uptime_seconds", "Seconds since the engine started.", time.Since(e.started).Seconds()))
	return out
}

// Ready reports why the node is not ready yet: the configuration model is
// unavailable, or the model has not been brought into the kernel since the
// start. A node without cluster quorum is ready: it forwards with the
// configuration it has.
func (e *Engine) Ready() error {
	if e.conf.err != nil {
		return errors.New("configuration model unavailable")
	}
	if e.conf.store == nil {
		return errors.New("configuration model not open")
	}
	if !e.conf.started.Load() {
		return errors.New("configuration not applied yet")
	}
	return nil
}
