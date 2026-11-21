package engine

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"time"

	"github.com/noahzmr/testudo/internal/cluster"
	"github.com/noahzmr/testudo/internal/confapply"
	"github.com/noahzmr/testudo/internal/confstore"
	"github.com/noahzmr/testudo/internal/identity"
	"github.com/noahzmr/testudo/internal/model"
	"github.com/noahzmr/testudo/internal/storage"
)

// MaxFailedMembers is how many members may fail to apply a change before
// it is rolled back for everyone. Zero: a change has to work everywhere.
const MaxFailedMembers = 0

// clusterCore is this node's place in a cluster. mgr is nil when the node
// was started without cluster addresses.
type clusterCore struct {
	mgr  *cluster.Manager
	wake chan struct{}
	// forwarded serves console API requests another member passed on; the
	// web layer installs it.
	forwarded func(http.ResponseWriter, *http.Request, string)
}

// openCluster prepares cluster membership. It runs after openConfig: the
// store exists, nothing has been applied yet.
func (e *Engine) openCluster() {
	c := &e.conf
	if e.cfg.ClusterRaft == "" || c.store == nil {
		return
	}
	name := e.cfg.NodeName
	if name == "" {
		name, _ = os.Hostname()
	}
	api := e.cfg.ClusterAPI
	if api == "" {
		log.Printf("cluster: no member API address; not starting")
		return
	}
	cl := &e.cluster
	cl.wake = make(chan struct{}, 1)
	mgr, err := cluster.NewManager(cluster.Config{
		ID: name, Name: name, Dir: filepath.Join(e.cfg.StorageDir, "cluster"),
		RaftBind: e.cfg.ClusterRaft, APIBind: api, RaftAdvertise: e.cfg.ClusterAdvertiseRaft, APIAdvertise: e.cfg.ClusterAdvertiseAPI,
		Store: c.store, Secrets: c.secrets, Build: buildID(),
		Forwarded: func(w http.ResponseWriter, r *http.Request, id string) {
			if cl.forwarded == nil {
				http.Error(w, "this member does not serve the console API", http.StatusServiceUnavailable)
				return
			}
			cl.forwarded(w, r, id)
		},
		Changed: func() {
			select {
			case cl.wake <- struct{}{}:
			default:
			}
		},
		MeshKey: func() string { return e.meshPublicKey(false) },
		Flows:   func() ([]byte, error) { return json.Marshal(e.localNodeFlows()) },
		Partner: e.haPartner,
		FailedOver: func(dead, partner string) {
			log.Printf("cluster: voter %s unreachable; its HA partner %s votes for the site now", dead, partner)
			go e.recordVoterFailover(dead, partner)
		},
	})
	if err != nil {
		log.Printf("cluster: %v", err)
		return
	}
	cl.mgr = mgr
	if err := mgr.Start(); err != nil {
		log.Printf("cluster: this member could not be opened: %v", err)
		return
	}
	e.joinApply()
}

// clusterNodeFor finds the model's node for a cluster member: members are
// named after the node's name or host name.
func clusterNodeFor(st *confstore.State, member string) *model.ClusterNode {
	for _, e := range st.List(model.KindClusterNode) {
		n := e.(*model.ClusterNode)
		if strings.EqualFold(n.Name, member) || strings.EqualFold(n.Hostname, member) {
			return n
		}
	}
	return nil
}

// haPartner names the cluster member that is the other node of member's
// enabled HA pair, or "".
func (e *Engine) haPartner(member string) string {
	mgr := e.cluster.mgr
	if e.conf.store == nil || mgr == nil || mgr.Node() == nil {
		return ""
	}
	st := e.conf.store.Current()
	me := clusterNodeFor(st, member)
	if me == nil {
		return ""
	}
	for _, obj := range st.List(model.KindHAPair) {
		p := obj.(*model.HAPair)
		if !p.Enabled || len(p.Nodes) != 2 || (p.Nodes[0].ID != me.ID && p.Nodes[1].ID != me.ID) {
			continue
		}
		other := p.Nodes[0].ID
		if other == me.ID {
			other = p.Nodes[1].ID
		}
		obj, ok := st.Get(model.KindClusterNode, other)
		if !ok {
			return ""
		}
		n := obj.(*model.ClusterNode)
		for id := range mgr.Node().State().Members {
			if strings.EqualFold(id, n.Name) || strings.EqualFold(id, n.Hostname) {
				return id
			}
		}
	}
	return ""
}

// recordVoterFailover audits a replaced voter and makes the model say who
// votes for the site now.
func (e *Engine) recordVoterFailover(dead, partner string) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	args, _ := json.Marshal(map[string]string{"unreachable": dead, "voter": partner})
	if err := e.store.InsertAudit(ctx, storage.AuditEntry{TS: time.Now(), Op: "cluster_voter_failover", Args: string(args),
		Actor: "system", Result: "ok"}); err != nil {
		log.Printf("cluster: audit: %v", err)
	}
	if e.conf.apply == nil {
		return
	}
	st := e.conf.store.Current()
	n := clusterNodeFor(st, partner)
	if n == nil {
		return
	}
	obj, ok := st.Get(model.KindSite, n.Site.ID)
	if !ok {
		return
	}
	site := *obj.(*model.Site)
	if site.Voter.ID == n.ID {
		return
	}
	site.Voter = model.Ref[model.ClusterNode]{ID: n.ID}
	raw, err := json.Marshal(&site)
	if err != nil {
		return
	}
	if _, pending := e.conf.apply.Pending(); pending {
		log.Printf("cluster: site %s votes through %s now; the model is updated after the pending change", site.Name, n.Name)
		return
	}
	ops := []confstore.Op{{Type: confstore.OpUpdate, Kind: model.KindSite, ID: site.ID, Object: raw, IfMatch: site.Version}}
	if _, err := e.conf.apply.Apply(ctx, "system", "voter failover", ops); err != nil {
		log.Printf("cluster: recording the new voter of site %s: %v", site.Name, err)
		return
	}
	if err := e.conf.apply.Confirm("system"); err != nil {
		log.Printf("cluster: confirming the new voter of site %s: %v", site.Name, err)
	}
}

// joinApply tells the apply engine that this node is a cluster member.
func (e *Engine) joinApply() {
	mgr := e.cluster.mgr
	if mgr == nil || mgr.Node() == nil || e.conf.apply == nil {
		return
	}
	e.conf.apply.SetCluster(&cluster.Applier{Node: mgr.Node(), Send: mgr.SendResult}, MaxFailedMembers)
}

// clusterLoop keeps this member in step with the cluster and checks for
// drift between what runs and the model.
func (e *Engine) clusterLoop(ctx context.Context) {
	cl := &e.cluster
	if cl.mgr == nil {
		return
	}
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	lastDrift := time.Now()
	for {
		select {
		case <-ctx.Done():
			cl.mgr.Close()
			return
		case <-cl.wake:
		case <-tick.C:
		}
		node := cl.mgr.Node()
		if node == nil || e.conf.apply == nil {
			continue
		}
		e.conf.apply.Sync(ctx)
		if node.IsLeader() && len(identity.MissingBuiltinRoles(e.conf.store.Current())) > 0 {
			e.seedRoles(ctx)
		}
		if time.Since(lastDrift) > 30*time.Second {
			lastDrift = time.Now()
			if what := e.conf.apply.Repair(ctx); what != "" {
				log.Printf("cluster: this member had drifted from the model (%s)", what)
			}
		}
	}
}

// Cluster returns this node's cluster manager, or nil.
func (e *Engine) Cluster() *cluster.Manager { return e.cluster.mgr }

// SetClusterForwarded installs the handler for console API requests that
// other members pass on to this one as the leader.
func (e *Engine) SetClusterForwarded(h func(http.ResponseWriter, *http.Request, string)) {
	e.cluster.forwarded = h
}

var errNoCluster = errors.New("this node was started without cluster addresses (--cluster-raft, --cluster-api)")

// ClusterStatus describes the cluster from this member.
func (e *Engine) ClusterStatus() any {
	type status struct {
		cluster.Status
		Enabled  bool                     `json:"enabled"`
		Applied  int64                    `json:"applied_index"`
		Override *confapply.LocalOverride `json:"override,omitempty"`
	}
	out := status{}
	if e.cluster.mgr == nil {
		if e.conf.store != nil {
			out.ModelIndex = e.conf.store.Current().Index()
		}
		return out
	}
	out.Status, out.Enabled = e.cluster.mgr.Status(), true
	if e.conf.apply != nil {
		out.Applied = e.conf.apply.Applied()
		if o, ok := e.conf.apply.CurrentOverride(); ok {
			out.Override = &o
		}
	}
	return out
}

// ClusterInit makes this node the first member of a new cluster.
func (e *Engine) ClusterInit(ctx context.Context) error {
	if e.cluster.mgr == nil {
		return errNoCluster
	}
	if p, pending := e.conf.apply.Pending(); pending {
		return errors.New("a change waits for confirmation (record " + itoa(p.Index) + "); settle it first")
	}
	if err := e.cluster.mgr.Init(ctx); err != nil {
		return err
	}
	e.joinApply()
	return nil
}

// ClusterJoin makes this node a member of an existing cluster.
func (e *Engine) ClusterJoin(ctx context.Context, token string) error {
	if e.cluster.mgr == nil {
		return errNoCluster
	}
	if err := e.cluster.mgr.Join(ctx, token); err != nil {
		return err
	}
	e.joinApply()
	return nil
}

// ClusterToken issues a join token.
func (e *Engine) ClusterToken(ttl time.Duration, voter bool) (string, error) {
	if e.cluster.mgr == nil {
		return "", errNoCluster
	}
	return e.cluster.mgr.NewToken(ttl, voter)
}

// ClusterMember changes a member: "remove", "promote", "demote".
func (e *Engine) ClusterMember(id, action string) error {
	mgr := e.cluster.mgr
	if mgr == nil {
		return errNoCluster
	}
	switch action {
	case "remove":
		return mgr.Remove(id)
	case "promote":
		return mgr.Promote(id)
	case "demote":
		return mgr.Demote(id)
	}
	return errors.New("unknown action " + action)
}

// ClusterTransfer hands leadership to another voter.
func (e *Engine) ClusterTransfer() error {
	if e.cluster.mgr == nil {
		return errNoCluster
	}
	return e.cluster.mgr.TransferLeadership()
}

// ClusterOverride puts a change into effect on this member only; see
// confapply.Engine.Override.
func (e *Engine) ClusterOverride(ctx context.Context, actor, reason string, ops []confstore.Op) (confapply.LocalOverride, error) {
	return e.conf.apply.Override(ctx, actor, reason, ops)
}

// ClusterResolveOverride ends the local override.
func (e *Engine) ClusterResolveOverride(ctx context.Context, actor string) (confapply.LocalOverride, error) {
	return e.conf.apply.ResolveOverride(ctx, actor)
}

// ClusterWritable reports whether a change made here can be decided: this
// node is not in a cluster, or it leads one. forward is true when another
// member leads and the request should go there.
func (e *Engine) ClusterWritable() (writable, forward bool) {
	mgr := e.cluster.mgr
	if mgr == nil || mgr.Node() == nil {
		return true, false
	}
	if mgr.Node().IsLeader() {
		return true, false
	}
	return false, true
}

// buildID names this build for the other members: the revision it was
// built from, where the toolchain recorded one.
func buildID() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	for _, s := range info.Settings {
		if s.Key == "vcs.revision" && len(s.Value) >= 12 {
			return s.Value[:12]
		}
	}
	if info.Main.Version != "" {
		return info.Main.Version
	}
	return "dev"
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for ; n > 0; n /= 10 {
		i--
		b[i] = byte('0' + n%10)
	}
	return string(b[i:])
}
