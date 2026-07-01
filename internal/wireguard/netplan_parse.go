package wireguard

import (
	"fmt"
	"strings"

	yaml "gopkg.in/yaml.v3"
)

// ConfiguredDevice is a WireGuard interface as declared in netplan - the
// "intent" half of the merged read. It carries no secrets (the private key line
// is intentionally ignored during parsing).
type ConfiguredDevice struct {
	Name       string
	Address    string // first configured address (CIDR)
	Addresses  []string
	ListenPort int
	Peers      []ConfiguredPeer
}

// ConfiguredPeer is one peer entry from a netplan wireguard tunnel (public only).
type ConfiguredPeer struct {
	PublicKey  string
	AllowedIPs []string
	Endpoint   string
	Keepalive  int
}

// netplanDoc is the subset of the netplan schema Testudo cares about. Both the
// modern (network.tunnels.<name>) layout and the fields WireGuard uses are
// covered. The interface private key ("key"/"keys.private") is deliberately not
// mapped so it never lands in a parsed struct.
type netplanDoc struct {
	Network struct {
		Tunnels map[string]netplanTunnel `yaml:"tunnels"`
	} `yaml:"network"`
}

type netplanTunnel struct {
	Mode      string   `yaml:"mode"`
	Addresses []string `yaml:"addresses"`
	Port      int      `yaml:"port"`
	Peers     []struct {
		Keys struct {
			Public string `yaml:"public"`
		} `yaml:"keys"`
		AllowedIPs []string `yaml:"allowed-ips"`
		Endpoint   string   `yaml:"endpoint"`
		Keepalive  int      `yaml:"keepalive"`
	} `yaml:"peers"`
}

// ParseNetplanTunnels parses one netplan YAML document and returns every
// WireGuard tunnel it declares (mode: wireguard). Non-wireguard tunnels are
// skipped. A parse error is returned so the caller can flag the file unreadable.
func ParseNetplanTunnels(content string) ([]ConfiguredDevice, error) {
	var doc netplanDoc
	if err := yaml.Unmarshal([]byte(content), &doc); err != nil {
		return nil, fmt.Errorf("parse netplan yaml: %w", err)
	}
	var out []ConfiguredDevice
	for name, t := range doc.Network.Tunnels {
		if !strings.EqualFold(t.Mode, "wireguard") {
			continue
		}
		cd := ConfiguredDevice{
			Name:       name,
			Addresses:  append([]string(nil), t.Addresses...),
			ListenPort: t.Port,
		}
		if len(t.Addresses) > 0 {
			cd.Address = t.Addresses[0]
		}
		for _, p := range t.Peers {
			if p.Keys.Public == "" {
				continue
			}
			cd.Peers = append(cd.Peers, ConfiguredPeer{
				PublicKey:  p.Keys.Public,
				AllowedIPs: append([]string(nil), p.AllowedIPs...),
				Endpoint:   p.Endpoint,
				Keepalive:  p.Keepalive,
			})
		}
		out = append(out, cd)
	}
	return out, nil
}

// ParseNetplanFiles parses many netplan documents (e.g. every file under
// /etc/netplan) and merges their tunnels by device name. Files that fail to
// parse are reported via the returned error list but do not abort the merge -
// one bad operator file shouldn't blind the whole view.
func ParseNetplanFiles(files map[string]string) (map[string]ConfiguredDevice, []error) {
	merged := map[string]ConfiguredDevice{}
	var errs []error
	for name, content := range files {
		devs, err := ParseNetplanTunnels(content)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", name, err))
			continue
		}
		for _, d := range devs {
			merged[d.Name] = d // last writer wins; netplan itself forbids dup keys
		}
	}
	return merged, errs
}
