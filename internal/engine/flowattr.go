package engine

import (
	"context"
	"net"
	"path/filepath"
	"time"

	"github.com/noahzmr/testudo/internal/flowattr"
	"github.com/noahzmr/testudo/internal/flows"
	"github.com/noahzmr/testudo/internal/lbrender"
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
