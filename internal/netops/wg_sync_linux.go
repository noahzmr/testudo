//go:build linux

package netops

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/noahzmr/testudo/internal/secrets"
)

// wgAlias marks the WireGuard devices this program created.
const wgAlias = "testudo"

func readKey(dir, ref string) (wgtypes.Key, error) {
	raw, err := (secrets.Store{Dir: dir}).Get(ref)
	if err != nil {
		return wgtypes.Key{}, err
	}
	return wgtypes.ParseKey(strings.TrimSpace(string(raw)))
}

func (w *Writer) syncWGDirect(spec WGSpec) error {
	if len(spec.Devices) > 0 && !filepath.IsAbs(spec.SecretDir) {
		return errors.New("wireguard sync: the secret directory must be an absolute path")
	}
	client, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("wireguard sync: %w", err)
	}
	defer client.Close()

	var errs []error
	want := map[string]bool{}
	for _, d := range spec.Devices {
		want[d.Name] = true
		fail := func(format string, a ...any) {
			errs = append(errs, fmt.Errorf("%s: %s", d.Name, fmt.Sprintf(format, a...)))
		}
		link, err := netlink.LinkByName(d.Name)
		if err != nil {
			if err := netlink.LinkAdd(&netlink.Wireguard{LinkAttrs: netlink.LinkAttrs{Name: d.Name}}); err != nil {
				fail("create: %v", err)
				continue
			}
			if link, err = netlink.LinkByName(d.Name); err != nil {
				fail("%v", err)
				continue
			}
			_ = netlink.LinkSetAlias(link, wgAlias)
		} else if link.Type() != "wireguard" {
			fail("a device of another type has this name")
			continue
		}

		// Only what differs is sent. Setting a private key, even the same
		// one, expires every peer's session keys, and replacing a peer
		// forgets its endpoint: a sync that rewrote everything would cut
		// every tunnel on every configuration change, including the one an
		// operator is using to make that change.
		cur, err := client.Device(d.Name)
		if err != nil {
			fail("read: %v", err)
			continue
		}
		var cfg wgtypes.Config
		if d.ListenPort > 0 && cur.ListenPort != d.ListenPort {
			port := d.ListenPort
			cfg.ListenPort = &port
		}
		if d.KeyRef != "" {
			key, err := readKey(spec.SecretDir, d.KeyRef)
			if err != nil {
				fail("private key %q: %v", d.KeyRef, err)
				continue
			}
			if key.PublicKey() != cur.PublicKey {
				cfg.PrivateKey = &key
			}
		}
		existing := map[wgtypes.Key]wgtypes.Peer{}
		for _, p := range cur.Peers {
			existing[p.PublicKey] = p
		}
		wanted := map[wgtypes.Key]bool{}
		bad := false
		for _, p := range d.Peers {
			pub, err := wgtypes.ParseKey(p.PublicKey)
			if err != nil {
				fail("peer public key: %v", err)
				bad = true
				break
			}
			wanted[pub] = true
			pc := wgtypes.PeerConfig{PublicKey: pub, ReplaceAllowedIPs: true}
			allowed := map[string]bool{}
			for _, a := range p.AllowedIPs {
				_, n, err := net.ParseCIDR(a)
				if err != nil {
					fail("peer allowed IP %q: %v", a, err)
					bad = true
					break
				}
				pc.AllowedIPs = append(pc.AllowedIPs, *n)
				allowed[n.String()] = true
			}
			var psk wgtypes.Key
			if p.PresharedRef != "" {
				if psk, err = readKey(spec.SecretDir, p.PresharedRef); err != nil {
					fail("preshared key %q: %v", p.PresharedRef, err)
					bad = true
					break
				}
			}
			pc.PresharedKey = &psk // the zero key removes a preshared key
			if p.Endpoint != "" {
				ep, err := net.ResolveUDPAddr("udp", p.Endpoint)
				if err != nil {
					fail("peer endpoint %q: %v", p.Endpoint, err)
					bad = true
					break
				}
				pc.Endpoint = ep
			}
			ka := time.Duration(p.Keepalive) * time.Second
			pc.PersistentKeepaliveInterval = &ka
			if have, ok := existing[pub]; ok {
				same := have.PresharedKey == psk && have.PersistentKeepaliveInterval == ka && len(have.AllowedIPs) == len(allowed)
				for _, n := range have.AllowedIPs {
					same = same && allowed[n.String()]
				}
				// A configured endpoint is only a starting point; the peer
				// may have roamed, and that is not a difference.
				if same {
					continue
				}
			}
			cfg.Peers = append(cfg.Peers, pc)
		}
		if bad {
			continue
		}
		for pub := range existing {
			if !wanted[pub] {
				cfg.Peers = append(cfg.Peers, wgtypes.PeerConfig{PublicKey: pub, Remove: true})
			}
		}
		if err := client.ConfigureDevice(d.Name, cfg); err != nil {
			fail("configure: %v", err)
			continue
		}

		// Addresses: add what is missing, remove what is not wanted.
		// Link-local addresses belong to the kernel.
		wantAddr := map[string]bool{}
		for _, a := range d.Addresses {
			addr, err := netlink.ParseAddr(a)
			if err != nil {
				fail("address %q: %v", a, err)
				continue
			}
			wantAddr[addr.IPNet.String()] = true
		}
		have, _ := netlink.AddrList(link, netlink.FAMILY_ALL)
		for _, a := range have {
			if a.IP.IsLinkLocalUnicast() {
				continue
			}
			if wantAddr[a.IPNet.String()] {
				delete(wantAddr, a.IPNet.String())
				continue
			}
			del := a
			if err := netlink.AddrDel(link, &del); err != nil {
				fail("remove address %s: %v", a.IPNet, err)
			}
		}
		for a := range wantAddr {
			addr, _ := netlink.ParseAddr(a)
			if err := netlink.AddrAdd(link, addr); err != nil && !errors.Is(err, os.ErrExist) {
				fail("add address %s: %v", a, err)
			}
		}
		if d.MTU > 0 && link.Attrs().MTU != d.MTU {
			if err := netlink.LinkSetMTU(link, d.MTU); err != nil {
				fail("mtu: %v", err)
			}
		}
		if err := netlink.LinkSetUp(link); err != nil {
			fail("up: %v", err)
		}
	}

	links, err := netlink.LinkList()
	if err != nil {
		errs = append(errs, err)
	}
	for _, link := range links {
		if link.Type() == "wireguard" && link.Attrs().Alias == wgAlias && !want[link.Attrs().Name] {
			if err := netlink.LinkDel(link); err != nil {
				errs = append(errs, fmt.Errorf("remove %s: %w", link.Attrs().Name, err))
			}
		}
	}
	return errors.Join(errs...)
}
