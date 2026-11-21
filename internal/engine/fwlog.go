package engine

import (
	"context"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/noahzmr/testudo/internal/events"
	"github.com/noahzmr/testudo/internal/fwrender"
	"github.com/noahzmr/testudo/internal/model"
	"github.com/noahzmr/testudo/internal/nflog"
)

// The packets filter rules log (and the policy's drop logging) go to a
// netfilter log group. The engine reads it, names the rule from the model,
// keeps the latest entries for the console and publishes each one, so the
// log export sends it on.

const fwLogKeep = 200

// fwLog holds the latest logged packets.
type fwLog struct {
	mu      sync.Mutex
	entries []events.FirewallLogPayload
	times   []time.Time
	names   map[uint32]string
}

// FirewallLogEntry is one logged packet as the console shows it.
type FirewallLogEntry struct {
	Time time.Time `json:"time"`
	events.FirewallLogPayload
}

// FirewallLog returns the latest logged packets, newest first.
func (e *Engine) FirewallLog(limit int) []FirewallLogEntry {
	l := &e.fwlog
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]FirewallLogEntry, 0, len(l.entries))
	for i := len(l.entries) - 1; i >= 0 && (limit <= 0 || len(out) < limit); i-- {
		out = append(out, FirewallLogEntry{Time: l.times[i], FirewallLogPayload: l.entries[i]})
	}
	return out
}

func (l *fwLog) ifname(idx uint32) string {
	if idx == 0 {
		return ""
	}
	if n, ok := l.names[idx]; ok {
		return n
	}
	name := ""
	if ifi, err := net.InterfaceByIndex(int(idx)); err == nil {
		name = ifi.Name
	}
	if l.names == nil {
		l.names = map[uint32]string{}
	}
	l.names[idx] = name
	return name
}

// describe names the rule behind a log prefix.
func (e *Engine) describe(p *events.FirewallLogPayload, prefix string) {
	if chain, ok := strings.CutPrefix(prefix, fwrender.LogDropPrefix); ok {
		p.Rule, p.Action, p.Chain = "default drop", "drop", chain
		return
	}
	id, ok := strings.CutPrefix(prefix, fwrender.LogRulePrefix)
	if !ok {
		p.Rule = prefix
		return
	}
	p.RuleID, p.Rule = id, id
	if e.conf.store == nil {
		return
	}
	if o, ok := e.conf.store.Current().Get(model.KindFilterRule, id); ok {
		r := o.(*model.FilterRule)
		p.Rule, p.Action = r.Name, r.Action
		p.Chain = map[string]string{"in": "input", "out": "output", "forward": "forward"}[r.Direction]
	}
}

// startFirewallLog reads the log group until ctx ends.
func (e *Engine) startFirewallLog(ctx context.Context) {
	if e.netops == nil {
		return
	}
	fd, err := e.netops.OpenNFLOG()
	if err != nil {
		log.Printf("firewall log: %v", err)
		return
	}
	r := nflog.NewReader(fd)
	go func() {
		<-ctx.Done()
		r.Close()
	}()
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		for {
			batch, err := r.Read()
			if err != nil {
				if ctx.Err() == nil {
					log.Printf("firewall log: %v", err)
				}
				return
			}
			e.fwlog.mu.Lock()
			for _, en := range batch {
				p := events.FirewallLogPayload{InIface: e.fwlog.ifname(en.InDev), OutIface: e.fwlog.ifname(en.OutDev),
					Proto: en.ProtoName(), SrcPort: en.SrcPort, DstPort: en.DstPort, Length: en.Length}
				if en.Src.IsValid() {
					p.Src, p.Dst = en.Src.String(), en.Dst.String()
				}
				e.describe(&p, en.Prefix)
				e.fwlog.entries = append(e.fwlog.entries, p)
				e.fwlog.times = append(e.fwlog.times, en.Time)
				if n := len(e.fwlog.entries); n > fwLogKeep {
					e.fwlog.entries = e.fwlog.entries[n-fwLogKeep:]
					e.fwlog.times = e.fwlog.times[n-fwLogKeep:]
				}
				e.bus.Publish(events.Event{Kind: events.KindFirewallLog, Time: en.Time, Source: "firewall", Payload: p})
			}
			e.fwlog.mu.Unlock()
		}
	}()
}
