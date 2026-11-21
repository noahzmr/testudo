package engine

import (
	"context"
	"fmt"
	"os"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/noahzmr/testudo/internal/events"
	"github.com/noahzmr/testudo/internal/logexport"
	"github.com/noahzmr/testudo/internal/model"
)

// The log export sends what the node records to the collectors the model
// names: logged packets, alerts, access events, audit rows and changes of
// the configuration. One exporter runs per log_export object that applies
// to the node; each takes the categories it asks for.

type logExports struct {
	mu   sync.Mutex
	runs map[string]*exportRun
}

type exportRun struct {
	x    *logexport.Exporter
	stop context.CancelFunc
}

// LogExportStatus reports every exporter of the node.
func (e *Engine) LogExportStatus() []logexport.Status {
	e.logx.mu.Lock()
	defer e.logx.mu.Unlock()
	out := make([]logexport.Status, 0, len(e.logx.runs))
	for _, r := range e.logx.runs {
		out = append(out, r.x.Status())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func facility(name string) int {
	if n, ok := strings.CutPrefix(name, "local"); ok {
		if v, err := strconv.Atoi(n); err == nil && v >= 0 && v <= 7 {
			return 16 + v
		}
	}
	return 20
}

func (e *Engine) exportHost() string {
	if e.cfg.NodeName != "" {
		return e.cfg.NodeName
	}
	h, _ := os.Hostname()
	return h
}

// reconcileExports starts, restarts and stops exporters to match the model.
func (e *Engine) reconcileExports(ctx context.Context) {
	want := map[string]logexport.Target{}
	if e.conf.store != nil {
		st := e.conf.store.Current()
		site, node := e.locate(st)
		for _, o := range st.List(model.KindLogExport) {
			if !model.AppliesTo(o, site, node) {
				continue
			}
			eff, _, err := model.Effective(o, site, node)
			if err != nil {
				continue
			}
			x := eff.(*model.LogExport)
			if !x.Enabled {
				continue
			}
			want[x.ID] = logexport.Target{Name: x.Name, Address: x.Address, Transport: x.Transport, Format: x.Format,
				Categories: append([]string(nil), x.Categories...), Facility: facility(x.Facility), CA: []byte(x.CA), ServerName: x.ServerName}
		}
	}
	l := &e.logx
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.runs == nil {
		l.runs = map[string]*exportRun{}
	}
	for id, r := range l.runs {
		if t, ok := want[id]; !ok || !reflect.DeepEqual(t, r.x.Target()) {
			r.stop()
			delete(l.runs, id)
		}
	}
	for id, t := range want {
		if _, ok := l.runs[id]; ok {
			continue
		}
		rctx, cancel := context.WithCancel(ctx)
		r := &exportRun{x: logexport.New(t, e.exportHost()), stop: cancel}
		l.runs[id] = r
		go r.x.Run(rctx)
	}
}

func (e *Engine) export(r logexport.Record) {
	e.logx.mu.Lock()
	defer e.logx.mu.Unlock()
	for _, run := range e.logx.runs {
		run.x.Send(r)
	}
}

func (e *Engine) exporting() bool {
	e.logx.mu.Lock()
	defer e.logx.mu.Unlock()
	return len(e.logx.runs) > 0
}

var alertSeverity = map[string]int{string(events.SevInfo): logexport.SevInfo, string(events.SevWarn): logexport.SevWarning,
	string(events.SevError): logexport.SevError, string(events.SevCritical): logexport.SevCritical}

// startLogExport follows the model's log exports and feeds them.
func (e *Engine) startLogExport(ctx context.Context) {
	if e.conf.store == nil {
		return
	}
	e.reconcileExports(ctx)
	changes, cancel := e.conf.store.Subscribe(64)
	sub := e.bus.SubscribeKinds(events.KindFirewallLog, events.KindAnomaly, events.KindIncident)
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		defer cancel()
		defer sub.Close()
		lastAudit := int64(-1)
		tick := time.NewTicker(2 * time.Second)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case ev := <-changes:
				for _, c := range ev.Changes {
					if c.Kind == model.KindLogExport || c.Kind == model.KindClusterNode {
						e.reconcileExports(ctx)
						break
					}
				}
				if ev.Resync {
					e.reconcileExports(ctx)
				}
				for _, c := range ev.Changes {
					e.export(logexport.Record{Time: time.Now(), Category: logexport.Config, Severity: logexport.SevNotice, Event: "change",
						Message: fmt.Sprintf("%s %s %q", c.Type, c.Kind, c.Name),
						Fields: map[string]string{"actor": ev.Actor, "record": strconv.FormatInt(ev.Index, 10), "kind": string(c.Kind),
							"object": c.Name, "change": string(c.Type)}})
				}
			case ev := <-sub.C():
				e.exportEvent(ev)
			case <-tick.C:
				if e.store == nil {
					continue
				}
				if !e.exporting() {
					lastAudit = -1 // start from now when an export appears
					continue
				}
				rows, last, err := e.store.AuditAfter(ctx, lastAudit, 500)
				if err != nil {
					continue
				}
				lastAudit = last
				for _, r := range rows {
					e.export(logexport.Record{Time: r.TS, Category: logexport.Audit, Severity: logexport.SevNotice, Event: r.Op,
						Message: r.Op, Fields: map[string]string{"actor": r.Actor, "result": r.Result, "args": r.Args,
							"peer_uid": strconv.FormatUint(uint64(r.PeerUID), 10)}})
				}
			}
		}
	}()
}

func (e *Engine) exportEvent(ev events.Event) {
	switch p := ev.Payload.(type) {
	case events.FirewallLogPayload:
		f := map[string]string{"rule": p.Rule, "action": p.Action, "chain": p.Chain, "in_iface": p.InIface, "out_iface": p.OutIface,
			"src": p.Src, "dst": p.Dst, "proto": p.Proto, "length": strconv.Itoa(p.Length)}
		if p.SrcPort != 0 {
			f["src_port"] = strconv.Itoa(int(p.SrcPort))
		}
		if p.DstPort != 0 {
			f["dst_port"] = strconv.Itoa(int(p.DstPort))
		}
		for k, v := range f {
			if v == "" {
				delete(f, k)
			}
		}
		sev := logexport.SevInfo
		if p.Action == "drop" || p.Action == "reject" {
			sev = logexport.SevNotice
		}
		e.export(logexport.Record{Time: ev.Time, Category: logexport.Firewall, Severity: sev, Event: firstNonEmpty(p.Action, "log"),
			Message: p.Rule, Fields: f})
	case events.AnomalyPayload:
		cat := logexport.Alerts
		if ev.Source == "pam" {
			cat = logexport.Access
		}
		sev, ok := alertSeverity[p.Severity]
		if !ok {
			sev = logexport.SevInfo
		}
		e.export(logexport.Record{Time: ev.Time, Category: cat, Severity: sev, Event: ev.Source, Message: p.Message,
			Fields: map[string]string{"source": ev.Source, "severity": p.Severity}})
	default:
		if ev.Kind == events.KindIncident {
			e.export(logexport.Record{Time: ev.Time, Category: logexport.Alerts, Severity: logexport.SevError, Event: "incident",
				Message: fmt.Sprint(ev.Payload)})
		}
	}
}
