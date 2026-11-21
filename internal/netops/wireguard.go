package netops

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl"
)

// WGDeviceInfo is a denormalised, secrets-free view of one WireGuard device.
// The private key is deliberately omitted - only the public key is ever
// surfaced or persisted (secrets rule).
type WGDeviceInfo struct {
	Name         string
	PublicKey    string // base64 public key (public material)
	ListenPort   int
	FirewallMark int
	Peers        []WGPeerInfo
}

// WGPeerInfo is a denormalised, secrets-free view of one WireGuard peer. The
// preshared key is never included.
type WGPeerInfo struct {
	PublicKey           string // base64 public key (public material)
	Endpoint            string // host:port or "" when unknown
	AllowedIPs          []string
	LastHandshake       time.Time // zero when never established
	ReceiveBytes        int64
	TransmitBytes       int64
	PersistentKeepalive time.Duration
}

// ListWGDevices returns every WireGuard device known to the kernel, sorted by
// name, carrying public keys only. Reading device state needs CAP_NET_ADMIN,
// so the read is routed through the query seam: in-process when this process
// holds the capability, via the privileged helper otherwise. A process with
// neither gets a permission error, which callers treat as a soft "not
// available" rather than a hard failure.
func (w *Writer) ListWGDevices() ([]WGDeviceInfo, error) {
	var out []WGDeviceInfo
	err := w.queryInto(Op{Kind: OpQueryWGDevices}, &out)
	return out, err
}

func (w *Writer) listWGDevicesDirect() ([]WGDeviceInfo, error) {
	c, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("wgctrl new: %w", err)
	}
	defer c.Close()

	devs, err := c.Devices()
	if err != nil {
		return nil, fmt.Errorf("wg devices: %w", err)
	}
	out := make([]WGDeviceInfo, 0, len(devs))
	for _, d := range devs {
		di := WGDeviceInfo{
			Name:         d.Name,
			PublicKey:    d.PublicKey.String(),
			ListenPort:   d.ListenPort,
			FirewallMark: d.FirewallMark,
		}
		for _, p := range d.Peers {
			pi := WGPeerInfo{
				PublicKey:           p.PublicKey.String(),
				LastHandshake:       p.LastHandshakeTime,
				ReceiveBytes:        p.ReceiveBytes,
				TransmitBytes:       p.TransmitBytes,
				PersistentKeepalive: p.PersistentKeepaliveInterval,
			}
			if p.Endpoint != nil {
				pi.Endpoint = p.Endpoint.String()
			}
			for _, aip := range p.AllowedIPs {
				pi.AllowedIPs = append(pi.AllowedIPs, aip.String())
			}
			di.Peers = append(di.Peers, pi)
		}
		out = append(out, di)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// netplanDir is the only directory the netplan ops will write into. It is a var
// (not a const) solely so tests can point it at a temp directory.
var netplanDir = "/etc/netplan"

// netplanMarker identifies a Testudo-rendered netplan file. RenderNetplan (in the
// wireguard package) emits this on the first line; SyncNetplan refuses to touch
// any file that lacks it, so an operator's own netplan is never clobbered.
const netplanMarker = "Managed by Testudo"

// NetplanFile is one netplan YAML file under /etc/netplan. Content may hold
// secrets (interface private keys), so it is never logged and is only surfaced
// to an authenticated operator viewing/editing their own config.
type NetplanFile struct {
	Name    string `json:"name"`
	Path    string `json:"path"`
	Content string `json:"content"`
	Managed bool   `json:"managed"` // carries the Testudo marker
}

// ListNetplan reads every *.yaml under /etc/netplan and returns them, sorted by
// name. It is a privileged READ (netplan files are often 0600) routed through
// the query seam, so it works from the unprivileged engine via the helper. Not
// write-gated - viewing config is not a mutation.
func (w *Writer) ListNetplan() ([]NetplanFile, error) {
	body, err := w.be().Query(Op{Kind: OpListNetplan})
	if err != nil {
		return nil, err
	}
	var out []NetplanFile
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("decode netplan list: %w", err)
	}
	return out, nil
}

func (w *Writer) listNetplanDirect() ([]byte, error) {
	entries, err := os.ReadDir(netplanDir)
	if err != nil {
		if os.IsNotExist(err) {
			return json.Marshal([]NetplanFile{})
		}
		return nil, fmt.Errorf("read %s: %w", netplanDir, err)
	}
	var files []NetplanFile
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		p := filepath.Join(netplanDir, e.Name())
		data, err := os.ReadFile(p)
		if err != nil {
			continue // unreadable entry - skip rather than fail the whole list
		}
		files = append(files, NetplanFile{
			Name:    e.Name(),
			Path:    p,
			Content: string(data),
			Managed: strings.Contains(string(data), netplanMarker),
		})
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Name < files[j].Name })
	return json.Marshal(files)
}

// netplanGenerate runs `netplan generate` as a dry-run validation of the YAML.
func netplanGenerate() error { return netplanRun("generate") }

// netplanRun execs `netplan <sub>` with a timeout and surfaces its output.
func netplanRun(sub string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "netplan", sub).CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("netplan %s: %s", sub, msg)
	}
	return nil
}

// parseAllowedIPs turns "10.0.0.5/32" style strings into net.IPNet, accepting a
// bare address as a host route.
func parseAllowedIPs(cidrs []string) ([]net.IPNet, error) {
	out := make([]net.IPNet, 0, len(cidrs))
	for _, s := range cidrs {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if !strings.Contains(s, "/") {
			ip := net.ParseIP(s)
			if ip == nil {
				return nil, fmt.Errorf("invalid allowed-ip %q", s)
			}
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			out = append(out, net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
			continue
		}
		_, ipnet, err := net.ParseCIDR(s)
		if err != nil {
			return nil, fmt.Errorf("invalid allowed-ip %q: %w", s, err)
		}
		out = append(out, *ipnet)
	}
	return out, nil
}

// shortKey truncates a base64 key for logging so full material never dominates a
// log line (still public, but keeps logs tidy and mirrors the UI's truncation).
func shortKey(k string) string {
	if len(k) <= 10 {
		return k
	}
	return k[:10] + "…"
}
