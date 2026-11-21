package engine

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/noahzmr/testudo/internal/flowattr"
	"github.com/noahzmr/testudo/internal/flowcorr"
	"github.com/noahzmr/testudo/internal/flows"
	"github.com/noahzmr/testudo/internal/lbrender"
	"github.com/noahzmr/testudo/internal/model"
	"github.com/noahzmr/testudo/internal/netops"
)

// The attribution index is rebuilt every few seconds from the model, the
// translated conntrack entries and the proxy's access log, and applied to
// flows wherever they are shown, stored or sent on.
const attrInterval = 3 * time.Second

// Attribute fills in where each flow belongs. Without an index yet the
// flows come back unchanged.
func (e *Engine) Attribute(stats []flows.FlowStats) []flows.FlowStats {
	x := e.attrIndex.Load()
	if x == nil {
		return stats
	}
	return x.Apply(stats)
}

func localIPs() []string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	var out []string
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok {
			out = append(out, n.IP.String())
		}
	}
	return out
}

func (e *Engine) attrLoop(ctx context.Context) {
	access := &flowattr.AccessLog{Path: filepath.Join(e.cfg.StorageDir, "proxy", lbrender.AccessLogFile)}
	tick := time.NewTicker(attrInterval)
	defer tick.Stop()
	for {
		in := flowattr.Input{Access: access.Read(time.Now()), LocalIPs: localIPs(), Now: time.Now()}
		if e.conf.store != nil {
			in.State = e.conf.store.Current()
			in.SiteID, in.NodeID = e.locate(in.State)
		}
		if e.netops != nil {
			// Only the translated entries: a busy router's table is large,
			// and the rest says nothing the flow table does not.
			if res, err := e.netops.ListConntrackQuery(netops.ConntrackQuery{NATOnly: true, Limit: 50000}); err == nil {
				in.Conntrack = res.Flows
			}
		}
		e.attrIndex.Store(flowattr.Build(in))
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// siteFlowLimit bounds what a member reports: the most recently active
// flows are the ones worth joining.
const siteFlowLimit = 2000

// localNodeFlows is this member's recent flows, attributed.
func (e *Engine) localNodeFlows() flowcorr.NodeFlows {
	out := flowcorr.NodeFlows{At: time.Now().UTC()}
	if e.conf.store != nil {
		st := e.conf.store.Current()
		site, node := e.locate(st)
		if s, ok := st.Get(model.KindSite, site); ok {
			out.Site = s.GetMeta().Name
		}
		if n, ok := st.Get(model.KindClusterNode, node); ok {
			out.Node = n.GetMeta().Name
		}
	}
	if out.Node == "" {
		out.Node = e.cfg.NodeName
	}
	if out.Node == "" {
		out.Node, _ = os.Hostname()
	}
	out.Flows = e.Attribute(flows.Decorate(e.flowAgg.TopByRecency(siteFlowLimit), e.dnsCache, e.procMatch))
	return out
}

// SiteFlows correlates what every member of the cluster saw: this
// member's flows and the others', fetched member to member. all also
// returns connections only one member saw.
func (e *Engine) SiteFlows(ctx context.Context, all bool) any {
	sets := []flowcorr.NodeFlows{e.localNodeFlows()}
	type node struct {
		Node  string `json:"node"`
		Site  string `json:"site"`
		Flows int    `json:"flows"`
		Error string `json:"error,omitempty"`
	}
	nodes := []node{{Node: sets[0].Node, Site: sets[0].Site, Flows: len(sets[0].Flows)}}
	if mgr := e.cluster.mgr; mgr != nil && mgr.Node() != nil {
		for id, res := range mgr.Gather(ctx, "/cluster/v1/flows") {
			var nf flowcorr.NodeFlows
			if res.Err == "" {
				if err := json.Unmarshal(res.Body, &nf); err != nil {
					res.Err = "unreadable answer"
				}
			}
			if res.Err != "" {
				nodes = append(nodes, node{Node: id, Error: res.Err})
				continue
			}
			sets = append(sets, nf)
			nodes = append(nodes, node{Node: nf.Node, Site: nf.Site, Flows: len(nf.Flows)})
		}
	}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].Node < nodes[j].Node })
	return map[string]any{"nodes": nodes, "connections": flowcorr.Correlate(sets, 30*time.Second, all)}
}
