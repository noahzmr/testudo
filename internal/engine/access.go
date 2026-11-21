package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/noahzmr/testudo/internal/confapply"
	"github.com/noahzmr/testudo/internal/confstore"
	"github.com/noahzmr/testudo/internal/events"
	"github.com/noahzmr/testudo/internal/model"
	"github.com/noahzmr/testudo/internal/netops"
	"github.com/noahzmr/testudo/internal/pam"
	"github.com/noahzmr/testudo/internal/storage"
)

// Privileged access over the model: the access manager (internal/pam)
// decides about requests; what can be reached, who may ask and which peers
// a user has come from the model (accessCatalog), and an active grant is an
// access_grant object of the model (modelGrants), which every member's
// packet filter renders.

// accessCatalog reads resources, policies and peers from the model.
type accessCatalog struct{ e *Engine }

func (c accessCatalog) state() *confstore.State {
	if c.e.conf.store == nil {
		return nil
	}
	return c.e.conf.store.Current()
}

// pamResource translates a resource of the model.
func pamResource(r *model.AccessResource) storage.PAMResource {
	out := storage.PAMResource{ID: r.ID, Name: r.Name, Login: r.Login, BrokerRef: r.BrokerRef}
	switch r.Type {
	case "ssh":
		out.Kind = pam.KindSSH
	case "rdp":
		out.Kind = pam.KindRDP
	default:
		out.Kind = pam.KindL3
	}
	out.CIDR = r.Target
	if ip := net.ParseIP(r.Target); ip != nil {
		if ip.To4() != nil {
			out.CIDR += "/32"
		} else {
			out.CIDR += "/128"
		}
	}
	if r.Protocol != "any" {
		out.Proto = r.Protocol
	}
	if lo, hi, ok := strings.Cut(r.Ports, "-"); r.Ports != "" {
		l, _ := strconv.Atoi(lo)
		out.PortLo = uint16(l)
		if ok {
			h, _ := strconv.Atoi(hi)
			out.PortHi = uint16(h)
		}
	}
	return out
}

func (c accessCatalog) Resource(id string) (storage.PAMResource, bool) {
	st := c.state()
	if st == nil {
		return storage.PAMResource{}, false
	}
	obj, ok := st.Get(model.KindAccessResource, id)
	if !ok {
		return storage.PAMResource{}, false
	}
	return pamResource(obj.(*model.AccessResource)), true
}

func (c accessCatalog) Resources() []storage.PAMResource {
	st := c.state()
	if st == nil {
		return nil
	}
	var out []storage.PAMResource
	for _, obj := range st.List(model.KindAccessResource) {
		out = append(out, pamResource(obj.(*model.AccessResource)))
	}
	return out
}

// requestable lists the policies access is asked for under: those that
// need an approval or a second factor. A policy that needs neither is a
// standing rule of the packet filter, with nothing to ask for.
func requestable(st *confstore.State) []*model.AccessPolicy {
	var out []*model.AccessPolicy
	for _, obj := range st.List(model.KindAccessPolicy) {
		if p := obj.(*model.AccessPolicy); p.RequiresApproval || p.RequiresMFA {
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func pamPolicy(p *model.AccessPolicy) storage.PAMPolicy {
	d, _ := time.ParseDuration(p.MaxDuration)
	subject := "users and groups of the policy"
	if p.Everyone {
		subject = "everyone"
	}
	return storage.PAMPolicy{ID: p.ID, Name: p.Name, Subject: subject, ResourceID: p.Resource.ID, MaxTTL: int64(d.Seconds()),
		RequiresApproval: p.RequiresApproval, RequiresMFA: p.RequiresMFA}
}

// modelUser finds the model's user with a user name.
func modelUser(st *confstore.State, name string) *model.User {
	for _, obj := range st.List(model.KindUser) {
		if u := obj.(*model.User); u.Username == name {
			return u
		}
	}
	return nil
}

func (c accessCatalog) Policies(subj pam.Subject, resourceID string) []storage.PAMPolicy {
	st := c.state()
	if st == nil {
		return nil
	}
	u := modelUser(st, subj.Name)
	groups := map[string]bool{}
	if u != nil {
		if u.Disabled {
			return nil
		}
		for _, g := range u.Groups {
			groups[g.ID] = true
		}
	}
	var out []storage.PAMPolicy
	for _, p := range requestable(st) {
		if p.Resource.ID != resourceID {
			continue
		}
		ok := p.Everyone
		for _, ref := range p.Users {
			ok = ok || (u != nil && ref.ID == u.ID)
		}
		for _, g := range p.Groups {
			ok = ok || groups[g.ID]
		}
		if ok {
			out = append(out, pamPolicy(p))
		}
	}
	return out
}

func (c accessCatalog) AllPolicies() []storage.PAMPolicy {
	st := c.state()
	if st == nil {
		return nil
	}
	var out []storage.PAMPolicy
	for _, p := range requestable(st) {
		out = append(out, pamPolicy(p))
	}
	return out
}

// PeerIPs returns the tunnel addresses of the user's enabled peers.
func (c accessCatalog) PeerIPs(user string) []string {
	st := c.state()
	if st == nil {
		return nil
	}
	u := modelUser(st, user)
	if u == nil {
		return nil
	}
	var out []string
	for _, obj := range st.List(model.KindWGPeer) {
		p := obj.(*model.WGPeer)
		if !p.Enabled || p.User.ID != u.ID {
			continue
		}
		for _, a := range p.AllowedIPs {
			if _, n, err := net.ParseCIDR(a); err == nil {
				if ones, bits := n.Mask.Size(); ones == bits {
					out = append(out, a)
				}
			}
		}
	}
	return out
}

func (c accessCatalog) PeerUsers() map[string]string {
	st := c.state()
	out := map[string]string{}
	if st == nil {
		return out
	}
	for _, obj := range st.List(model.KindWGPeer) {
		p := obj.(*model.WGPeer)
		if u, ok := st.Get(model.KindUser, p.User.ID); ok && p.User.ID != "" {
			out[p.PublicKey] = u.(*model.User).Username
		}
	}
	return out
}

// modelGrants makes grants objects of the model.
type modelGrants struct{ e *Engine }

func (m modelGrants) Grant(ctx context.Context, g storage.PAMGrant) error {
	st := m.e.conf.store.Current()
	u := modelUser(st, g.User)
	if u == nil {
		return fmt.Errorf("%s is not a user of the model", g.User)
	}
	ends := g.EndsAt.UTC()
	obj := &model.AccessGrant{Meta: model.Meta{ID: confstore.NewID(), Name: g.ID, Description: "Access for " + g.User},
		Resource: model.Ref[model.AccessResource]{ID: g.ResourceID}, User: model.Ref[model.User]{ID: u.ID}, Ends: &ends,
		Reason: g.Justification, ApprovedBy: g.ApprovedBy, BreakGlass: g.BreakGlass, Request: g.ID}
	if _, ok := st.Get(model.KindAccessPolicy, g.PolicyID); ok {
		obj.Policy = model.Ref[model.AccessPolicy]{ID: g.PolicyID}
	}
	raw, err := json.Marshal(obj)
	if err != nil {
		return err
	}
	return m.e.systemChange(ctx, "access grant "+g.ID, []confstore.Op{{Type: confstore.OpCreate, Kind: model.KindAccessGrant, ID: obj.ID, Object: raw}})
}

func (m modelGrants) Ungrant(ctx context.Context, request string) error {
	for _, obj := range m.e.conf.store.Current().List(model.KindAccessGrant) {
		if g := obj.(*model.AccessGrant); g.Request == request || g.ID == request {
			return m.e.systemChange(ctx, "end of access grant "+request,
				[]confstore.Op{{Type: confstore.OpDelete, Kind: model.KindAccessGrant, ID: g.ID, IfMatch: g.Version}})
		}
	}
	return nil
}

// systemChange applies and confirms ops as the system, here when this node
// may decide, or through the leader. A change waiting for confirmation
// delays it a little; then it gives up and the caller tries again later.
func (e *Engine) systemChange(ctx context.Context, reason string, ops []confstore.Op) error {
	for attempt := 0; ; attempt++ {
		err := e.systemChangeOnce(ctx, reason, ops)
		if (errors.Is(err, confapply.ErrPending) || errors.Is(err, confapply.ErrNotLeader)) && attempt < 5 {
			select {
			case <-ctx.Done():
				return err
			case <-time.After(2 * time.Second):
			}
			continue
		}
		return err
	}
}

func (e *Engine) systemChangeOnce(ctx context.Context, reason string, ops []confstore.Op) error {
	if e.conf.apply == nil {
		return errors.New("the configuration model is unavailable")
	}
	if _, forward := e.ClusterWritable(); !forward {
		if _, err := e.conf.apply.Apply(ctx, "system", reason, ops); err != nil {
			return err
		}
		return e.conf.apply.Confirm("system")
	}
	// Through the leader, as the system.
	id, _ := json.Marshal(map[string]any{"name": "system", "permissions": []string{"access:write"}})
	send := func(method, path string, body []byte, ifMatch int64) error {
		req := httptest.NewRequest(method, path, bytes.NewReader(body)).WithContext(ctx)
		req.Header.Set("Content-Type", "application/json")
		if ifMatch > 0 {
			req.Header.Set("If-Match", fmt.Sprintf(`"%d"`, ifMatch))
		}
		rec := httptest.NewRecorder()
		e.cluster.mgr.Forward(rec, req, string(id))
		switch {
		case rec.Code == http.StatusLocked:
			return confapply.ErrPending
		case rec.Code >= 300:
			return fmt.Errorf("the leader refused %s %s: %d %s", method, path, rec.Code, strings.TrimSpace(rec.Body.String()))
		}
		return nil
	}
	for _, op := range ops {
		info, ok := model.Lookup(string(op.Kind))
		if !ok {
			return fmt.Errorf("unknown kind %s", op.Kind)
		}
		var err error
		switch op.Type {
		case confstore.OpCreate:
			err = send("POST", "/api/v1/"+info.Plural, op.Object, 0)
		case confstore.OpUpdate:
			err = send("PUT", "/api/v1/"+info.Plural+"/"+op.ID, op.Object, op.IfMatch)
		case confstore.OpDelete:
			err = send("DELETE", "/api/v1/"+info.Plural+"/"+op.ID, nil, op.IfMatch)
		}
		if err != nil {
			return err
		}
		if err := send("POST", "/api/v1/apply/confirm", nil, 0); err != nil {
			return err
		}
	}
	return nil
}

// grantGrace is how long after its end a grant may stay before the leader
// removes it: the member that gave it normally does that on time, with its
// capture and brokered session.
const grantGrace = 30 * time.Second

// grantLoop removes the grants whose time is up when the member that gave
// them did not (it may be down), and on every member cuts the connections
// of grants that disappear.
func (e *Engine) grantLoop(ctx context.Context) {
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	type seen struct {
		peers  []string
		target string
	}
	known := map[string]seen{}
	var pruned time.Time
	broken := map[string]int64{}
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		if e.conf.store == nil {
			continue
		}
		if time.Since(pruned) > time.Hour && e.LeadsCluster() && e.conf.secrets.Dir != "" {
			if n := pruneRequests(e.conf.secrets, time.Now()); n > 0 {
				log.Printf("access: %d ended request(s) left the shared store", n)
			}
			if e.store != nil {
				broken = e.reportBrokenChains(ctx, broken)
			}
			pruned = time.Now()
		}
		st := e.conf.store.Current()
		cat := accessCatalog{e}
		now := time.Now()
		current := map[string]seen{}
		var overdue []confstore.Op
		for _, obj := range st.List(model.KindAccessGrant) {
			g := obj.(*model.AccessGrant)
			u, _ := st.Get(model.KindUser, g.User.ID)
			res, ok := cat.Resource(g.Resource.ID)
			if u != nil && ok {
				current[g.ID] = seen{peers: cat.PeerIPs(u.(*model.User).Username), target: res.CIDR}
			}
			if g.Ends != nil && now.After(g.Ends.Add(grantGrace)) {
				overdue = append(overdue, confstore.Op{Type: confstore.OpDelete, Kind: model.KindAccessGrant, ID: g.ID, IfMatch: g.Version})
			}
		}
		for id, s := range known {
			if _, still := current[id]; !still {
				if n := e.killGrantFlows(s.peers, s.target); n > 0 {
					log.Printf("access: grant %s ended; %d connection(s) cut", id, n)
				}
			}
		}
		known = current
		if len(overdue) > 0 && e.LeadsCluster() {
			if err := e.systemChange(ctx, "access grants past their end", overdue); err != nil {
				log.Printf("access: removing grants past their end: %v", err)
			}
		}
	}
}

// killGrantFlows cuts the tracked connections from the peers to the
// resource.
func (e *Engine) killGrantFlows(peers []string, target string) int {
	if e.netops == nil || len(peers) == 0 || target == "" {
		return 0
	}
	_, dst, err := net.ParseCIDR(target)
	if err != nil {
		return 0
	}
	var srcs []string
	from := map[string]bool{}
	for _, p := range peers {
		if ip, _, err := net.ParseCIDR(p); err == nil {
			srcs = append(srcs, ip.String())
			from[ip.String()] = true
		}
	}
	res, err := e.netops.ListConntrackQuery(netops.ConntrackQuery{SrcIPs: srcs, DstCIDR: dst.String()})
	if err != nil {
		return 0
	}
	n := 0
	for _, f := range res.Flows {
		if from[f.OrigSrc] && dst.Contains(net.ParseIP(f.OrigDst)) {
			if e.netops.FlushConntrack(f) == nil {
				n++
			}
		}
	}
	return n
}

// migratePAMCatalog moves the resources and policies the access manager
// kept in its database, and its peer bindings, into the model, once:
// what the model has by name already is left as it is.
func (e *Engine) migratePAMCatalog(ctx context.Context) {
	if e.store == nil || e.conf.store == nil {
		return
	}
	resources, _ := e.store.ListPAMResources(ctx)
	policies, _ := e.store.ListPAMPolicies(ctx)
	bindings, _ := e.store.WGPeerUsers(ctx)
	if len(resources) == 0 && len(policies) == 0 && len(bindings) == 0 {
		return
	}
	st := e.conf.store.Current()
	byName := map[model.Kind]map[string]string{}
	for _, k := range []model.Kind{model.KindAccessResource, model.KindAccessPolicy} {
		byName[k] = map[string]string{}
		for _, obj := range st.List(k) {
			byName[k][obj.GetMeta().Name] = obj.GetMeta().ID
		}
	}
	var ops []confstore.Op
	add := func(e model.Entity) {
		raw, _ := json.Marshal(e)
		ops = append(ops, confstore.Op{Type: confstore.OpCreate, Kind: e.Kind(), ID: e.GetMeta().ID, Object: raw})
	}
	resID := map[string]string{} // old id -> model id
	for _, r := range resources {
		name := safeObjName(r.Name)
		if id, ok := byName[model.KindAccessResource][name]; ok {
			resID[r.ID] = id
			continue
		}
		m := &model.AccessResource{Meta: model.Meta{ID: confstore.NewID(), Name: name, Description: "Moved from the access manager"},
			Type: "network", Target: strings.TrimSuffix(strings.TrimSuffix(r.CIDR, "/32"), "/128"), Protocol: "any",
			Login: r.Login, BrokerRef: r.BrokerRef}
		switch r.Kind {
		case pam.KindSSH:
			m.Type = "ssh"
		case pam.KindRDP:
			m.Type = "rdp"
		}
		if r.Proto != "" {
			m.Protocol = r.Proto
		}
		if r.PortLo != 0 {
			m.Ports = strconv.Itoa(int(r.PortLo))
			if r.PortHi > r.PortLo {
				m.Ports += "-" + strconv.Itoa(int(r.PortHi))
			}
		}
		resID[r.ID] = m.ID
		add(m)
	}
	polID := map[string]string{} // old id -> model id
	for _, p := range policies {
		name := safeObjName(p.Name)
		if id, ok := byName[model.KindAccessPolicy][name]; ok {
			polID[p.ID] = id
			continue
		}
		if resID[p.ResourceID] == "" {
			continue
		}
		m := &model.AccessPolicy{Meta: model.Meta{ID: confstore.NewID(), Name: name, Description: "Moved from the access manager"},
			Resource: model.Ref[model.AccessResource]{ID: resID[p.ResourceID]}, MaxDuration: fmt.Sprintf("%ds", max(p.MaxTTL, 60)),
			RequiresApproval: p.RequiresApproval, RequiresMFA: p.RequiresMFA}
		kind, value, _ := strings.Cut(p.Subject, ":")
		switch {
		case kind == "user" && modelUser(st, value) != nil:
			m.Users = []model.Ref[model.User]{{ID: modelUser(st, value).ID}}
		case kind == "role" && value == "viewer":
			m.Everyone = true
		default:
			log.Printf("access: policy %q (%s) has no counterpart in the model; give it users or groups there", p.Name, p.Subject)
			continue
		}
		if !m.RequiresApproval && !m.RequiresMFA {
			// Asked for before; asking stays the way to get it.
			m.RequiresApproval = true
		}
		polID[p.ID] = m.ID
		add(m)
	}
	// Grants that were active when the access manager still wrote firewall
	// rules become grants of the model, so they last until their end.
	ops = append(ops, activeGrantOps(st, mustList(e.store.ListPAMGrants(ctx, []string{pam.StateActive}, 1000)), resID, polID, time.Now())...)
	for _, obj := range st.List(model.KindWGPeer) {
		p := obj.(*model.WGPeer)
		if p.User.ID != "" {
			continue
		}
		if u := modelUser(st, bindings[p.PublicKey]); u != nil {
			c := *p
			c.User = model.Ref[model.User]{ID: u.ID}
			raw, _ := json.Marshal(&c)
			ops = append(ops, confstore.Op{Type: confstore.OpUpdate, Kind: model.KindWGPeer, ID: p.ID, Object: raw, IfMatch: p.Version})
		}
	}
	if len(ops) == 0 {
		return
	}
	if err := e.systemChange(ctx, "access resources, policies and active grants moved into the model", ops); err != nil {
		log.Printf("access: moving resources and policies into the model: %v", err)
		return
	}
	log.Printf("access: moved %d object(s) of the access manager into the model", len(ops))
}

func safeObjName(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteRune('-')
		}
	}
	out := strings.Trim(b.String(), "-._")
	if out == "" {
		out = "resource"
	}
	if len(out) > 63 {
		out = out[:63]
	}
	return out
}

func mustList(gs []storage.PAMGrant, err error) []storage.PAMGrant {
	if err != nil {
		log.Printf("access: active grants not read: %v", err)
		return nil
	}
	return gs
}

// activeGrantOps returns the model grants for active requests of the access
// manager that have none yet. resID and polID map the manager's ids to the
// model's.
func activeGrantOps(st *confstore.State, active []storage.PAMGrant, resID, polID map[string]string, now time.Time) []confstore.Op {
	have := map[string]bool{}
	for _, obj := range st.List(model.KindAccessGrant) {
		have[obj.(*model.AccessGrant).Request] = true
	}
	var ops []confstore.Op
	for _, g := range active {
		if have[g.ID] || !g.EndsAt.After(now) {
			continue
		}
		res := resID[g.ResourceID]
		if res == "" {
			if _, ok := st.Get(model.KindAccessResource, g.ResourceID); ok {
				res = g.ResourceID
			}
		}
		u := modelUser(st, g.User)
		if res == "" || u == nil {
			log.Printf("access: active grant %s of %s has no resource or user in the model and ends now", g.ID, g.User)
			continue
		}
		ends := g.EndsAt.UTC()
		obj := &model.AccessGrant{Meta: model.Meta{ID: confstore.NewID(), Name: g.ID, Description: "Access for " + g.User},
			Resource: model.Ref[model.AccessResource]{ID: res}, User: model.Ref[model.User]{ID: u.ID}, Ends: &ends,
			Reason: g.Justification, ApprovedBy: g.ApprovedBy, BreakGlass: g.BreakGlass, Request: g.ID}
		if id := polID[g.PolicyID]; id != "" {
			obj.Policy = model.Ref[model.AccessPolicy]{ID: id}
		}
		raw, _ := json.Marshal(obj)
		ops = append(ops, confstore.Op{Type: confstore.OpCreate, Kind: model.KindAccessGrant, ID: obj.ID, Object: raw})
	}
	return ops
}

// reportBrokenChains checks every member's access-log chain and raises an
// alert for each one that broke since the last check. was is what the last
// check found; the result is what this one did.
func (e *Engine) reportBrokenChains(ctx context.Context, was map[string]int64) map[string]int64 {
	now := map[string]int64{}
	for _, c := range e.accessStore().Chains(ctx) {
		if c.BrokenAt == 0 {
			continue
		}
		now[c.Member] = c.BrokenAt
		if was[c.Member] != c.BrokenAt {
			e.bus.Publish(events.Event{Kind: events.KindAnomaly, Time: time.Now(), Source: "pam",
				Payload: events.AnomalyPayload{Severity: string(events.SevError),
					Message: fmt.Sprintf("access log of %s was changed: its hash chain breaks at row %d", c.Member, c.BrokenAt)}})
		}
	}
	return now
}
