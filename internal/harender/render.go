// Package harender turns an HA pair of the model into what the two nodes
// run: keepalived (VRRP: which node holds the virtual addresses) and
// conntrackd (the connection table, kept in step over the sync link), and
// the two scripts that hand the connection table over when a node becomes
// active or steps back.
package harender

import (
	"fmt"
	"net"
	"path/filepath"
	"sort"
	"strings"

	"github.com/noahzmr/testudo/internal/confstore"
	"github.com/noahzmr/testudo/internal/model"
)

// Options are the node-local facts.
type Options struct {
	SiteID, NodeID string
	// Dir holds the configuration and scripts; it has to be writable by
	// root only, because keepalived runs the scripts as root. RunDir holds
	// pid files, the lock and conntrackd's control socket; its path has to
	// be short (a UNIX socket path has at most 107 characters).
	Dir, RunDir string
}

// File names in Dir.
const (
	KeepalivedConf = "keepalived.conf"
	ConntrackdConf = "conntrackd.conf"
	MasterScript   = "become-active.sh"
	BackupScript   = "become-standby.sh"
	SyncPort       = 3780
)

// Result is what the HA stage applies on this node.
type Result struct {
	// Enabled is false when this node is in no enabled pair; then nothing
	// of HA runs here.
	Enabled bool              `json:"enabled"`
	Pair    string            `json:"pair,omitempty"`
	Files   map[string]string `json:"files,omitempty"`
	// Interfaces carry VRRP; SyncInterface carries conntrackd; Peer is the
	// partner's sync address. The packet filter lets these in.
	Interfaces    []string `json:"interfaces,omitempty"`
	SyncInterface string   `json:"sync_interface,omitempty"`
	Peer          string   `json:"peer,omitempty"`
	VirtualIPs    []string `json:"virtual_ips,omitempty"`
}

// Render builds the node's HA setup.
func Render(st *confstore.State, opt Options) (Result, error) {
	var res Result
	var pair *model.HAPair
	for _, e := range st.List(model.KindHAPair) {
		p := e.(*model.HAPair)
		if !p.Enabled || !model.AppliesTo(p, opt.SiteID, opt.NodeID) {
			continue
		}
		for _, n := range p.Nodes {
			if n.ID == opt.NodeID {
				if pair != nil {
					return res, fmt.Errorf("harender: node is in two HA pairs, %q and %q", pair.Name, p.Name)
				}
				pair = p
			}
		}
	}
	if pair == nil {
		return res, nil
	}
	var me, peer *model.ClusterNode
	index := 0
	for i, r := range pair.Nodes {
		e, ok := st.Get(model.KindClusterNode, r.ID)
		if !ok {
			return res, fmt.Errorf("harender: pair %q names a node that does not exist", pair.Name)
		}
		if r.ID == opt.NodeID {
			me, index = e.(*model.ClusterNode), i
		} else {
			peer = e.(*model.ClusterNode)
		}
	}
	if me.SyncAddress == "" || peer.SyncAddress == "" {
		return res, fmt.Errorf("harender: pair %q: both nodes need an address on the sync link", pair.Name)
	}
	priority := me.VRRPPriority
	if priority == 0 {
		priority = []int{150, 100}[index]
	}
	advert := pair.AdvertMs
	if advert == 0 {
		advert = 1000
	}
	res = Result{Enabled: true, Pair: pair.Name, Files: map[string]string{}, SyncInterface: pair.SyncInterface, Peer: peer.SyncAddress}

	ctl := func(flag string) string {
		return fmt.Sprintf("/usr/sbin/conntrackd -C %s %s", filepath.Join(opt.Dir, ConntrackdConf), flag)
	}
	// Becoming active: put the partner's connections into the kernel,
	// empty the local cache, ask the partner for everything again and send
	// it ours. Stepping back: start over with the kernel's table and stop
	// pushing state.
	res.Files[MasterScript] = "#!/bin/sh\n# Written by testudo for HA pair " + pair.Name + ".\n" +
		ctl("-c") + "\n" + ctl("-f") + "\n" + ctl("-R") + "\n" + ctl("-B") + "\nexit 0\n"
	res.Files[BackupScript] = "#!/bin/sh\n# Written by testudo for HA pair " + pair.Name + ".\n" +
		ctl("-t") + "\n" + ctl("-n") + "\nexit 0\n"

	var k strings.Builder
	fmt.Fprintf(&k, "# Written by testudo for HA pair %s; changes are overwritten.\n", pair.Name)
	fmt.Fprintf(&k, "global_defs {\n  router_id %s\n  enable_script_security\n  script_user root\n  vrrp_version 3\n}\n", word(me.Name))
	insts := append([]model.VRRPInstance(nil), pair.Instances...)
	sort.Slice(insts, func(i, j int) bool { return insts[i].VRID < insts[j].VRID })
	names := make([]string, 0, len(insts))
	for _, in := range insts {
		names = append(names, fmt.Sprintf("vi%d", in.VRID))
	}
	fmt.Fprintf(&k, "vrrp_sync_group %s {\n  group {\n", word(pair.Name))
	for _, n := range names {
		fmt.Fprintf(&k, "    %s\n", n)
	}
	fmt.Fprintf(&k, "  }\n  notify_master %q\n  notify_backup %q\n  notify_fault %q\n}\n",
		filepath.Join(opt.Dir, MasterScript), filepath.Join(opt.Dir, BackupScript), filepath.Join(opt.Dir, BackupScript))
	seen := map[string]bool{}
	for i, in := range insts {
		fmt.Fprintf(&k, "vrrp_instance %s {\n  state BACKUP\n  interface %s\n  virtual_router_id %d\n  priority %d\n  advert_int %.2f\n",
			names[i], in.Interface, in.VRID, priority, float64(advert)/1000)
		if !pair.Preempt {
			k.WriteString("  nopreempt\n")
		}
		k.WriteString("  virtual_ipaddress {\n")
		for _, ip := range in.VirtualIPs {
			fmt.Fprintf(&k, "    %s dev %s\n", ip, in.Interface)
			res.VirtualIPs = append(res.VirtualIPs, ip)
		}
		k.WriteString("  }\n}\n")
		if !seen[in.Interface] {
			seen[in.Interface] = true
			res.Interfaces = append(res.Interfaces, in.Interface)
		}
	}
	res.Files[KeepalivedConf] = k.String()

	fam := "IPv4"
	if ip := net.ParseIP(me.SyncAddress); ip != nil && ip.To4() == nil {
		fam = "IPv6"
	}
	var c strings.Builder
	fmt.Fprintf(&c, "# Written by testudo for HA pair %s; changes are overwritten.\n", pair.Name)
	fmt.Fprintf(&c, "Sync {\n  Mode FTFW {\n    DisableExternalCache Off\n  }\n  UDP {\n    %s_address %s\n    %s_Destination_Address %s\n    Port %d\n    Interface %s\n    Checksum on\n  }\n}\n",
		fam, me.SyncAddress, fam, peer.SyncAddress, SyncPort, pair.SyncInterface)
	fmt.Fprintf(&c, "General {\n  HashSize 32768\n  HashLimit 131072\n  LockFile %s\n  UNIX {\n    Path %s\n  }\n  Syslog off\n  NetlinkEventsReliable On\n",
		filepath.Join(opt.RunDir, "conntrackd.lock"), filepath.Join(opt.RunDir, "conntrackd.ctl"))
	// The sync link's own traffic and loopback stay out of the sync; they
	// belong to one node and never move to the partner.
	c.WriteString("  Filter From Kernelspace {\n    Address Ignore {\n      IPv4_address 127.0.0.1\n      IPv6_address ::1\n")
	for _, a := range []string{me.SyncAddress, peer.SyncAddress} {
		if net.ParseIP(a).To4() != nil {
			fmt.Fprintf(&c, "      IPv4_address %s\n", a)
		} else {
			fmt.Fprintf(&c, "      IPv6_address %s\n", a)
		}
	}
	c.WriteString("    }\n  }\n}\n")
	res.Files[ConntrackdConf] = c.String()
	sort.Strings(res.Interfaces)
	return res, nil
}

func word(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' {
			return r
		}
		return '_'
	}, s)
}
