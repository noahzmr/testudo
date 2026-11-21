package engine

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"strings"

	"github.com/noahzmr/testudo/internal/confimport"
	"github.com/noahzmr/testudo/internal/confstore"
	"github.com/noahzmr/testudo/internal/firewall"
	"github.com/noahzmr/testudo/internal/model"
)

// migrateFirewallFile moves the policy file of the old firewall manager
// (firewall.json) into the model, once: its default policy and baseline
// when the model has none, its rules, port forwards and masquerades, and
// the rules the old WireGuard provisioner kept there. What has no
// counterpart is logged and recorded in the audit log by name; the file is
// kept as firewall.json.migrated. A node the model does not know yet gets a
// site and a node record first, so the packet filter does not fall back to
// nothing on an upgrade.
func (e *Engine) migrateFirewallFile(ctx context.Context) {
	if e.conf.apply == nil {
		return
	}
	path := firewallPolicyPath(e.cfg)
	pol, ok, err := firewall.Store{Path: path}.Load()
	if !ok {
		return
	}
	if err != nil {
		log.Printf("firewall: %s cannot be read, and stays where it is: %v", path, err)
		return
	}
	empty := len(pol.Rules) == 0 && len(pol.Forwards) == 0 && len(pol.Masquerades) == 0 && !pol.Enforce
	if !empty {
		st := e.conf.store.Current()
		_, node := e.locate(st)
		if node == "" {
			var err error
			if node, err = e.createSelf(ctx); err != nil {
				log.Printf("firewall: %s stays: this node is not in the model and could not be added: %v", path, err)
				return
			}
			st = e.conf.store.Current()
		}
		res := confimport.TranslateFirewall(confimport.Into{State: st, NodeID: node}, &pol, nil)
		if len(res.Ops) > 0 {
			if err := e.systemChange(ctx, "firewall.json moved into the model", res.Ops); err != nil {
				log.Printf("firewall: moving %s into the model: %v (tried again at the next start)", path, err)
				return
			}
		}
		for _, n := range res.Notes {
			log.Printf("firewall: %s", n)
		}
		args, _ := json.Marshal(map[string]any{"objects": len(res.Ops), "notes": res.Notes})
		e.Audit("system", "firewall_migration", string(args), nil)
		log.Printf("firewall: %s moved into the model (%d objects)", path, len(res.Ops))
	}
	if err := os.Rename(path, path+".migrated"); err != nil {
		log.Printf("firewall: %v", err)
	}
}

// createSelf adds a site and this node to a model that has neither, the way
// a single node of an older install becomes a cluster of one.
func (e *Engine) createSelf(ctx context.Context) (string, error) {
	host := e.cfg.NodeName
	if host == "" {
		host, _ = os.Hostname()
	}
	host = strings.ToLower(safeObjName(host))
	st := e.conf.store.Current()
	var ops []confstore.Op
	siteID := ""
	if sites := st.List(model.KindSite); len(sites) > 0 {
		siteID = sites[0].GetMeta().ID
	} else {
		siteID = confstore.NewID()
		raw, _ := json.Marshal(&model.Site{Meta: model.Meta{ID: siteID, Name: "default", Description: "The site this node was installed at"}})
		ops = append(ops, confstore.Op{Type: confstore.OpCreate, Kind: model.KindSite, ID: siteID, Object: raw})
	}
	nodeID := confstore.NewID()
	raw, _ := json.Marshal(&model.ClusterNode{Meta: model.Meta{ID: nodeID, Name: host}, Site: model.Ref[model.Site]{ID: siteID},
		Hostname: host, Address: "127.0.0.1"})
	ops = append(ops, confstore.Op{Type: confstore.OpCreate, Kind: model.KindClusterNode, ID: nodeID, Object: raw})
	return nodeID, e.systemChange(ctx, "this node, for the firewall policy moved into the model", ops)
}
