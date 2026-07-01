package web

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/noahzmr/testudo/internal/engine"
	"github.com/noahzmr/testudo/internal/wireguard"
)

// handleWireGuardProvision provisions a peer as a write-gated, audit-logged
// transaction with rollback (G2). In server-side-keygen mode it returns the
// client config exactly once in the JSON response (containing a PRIVATE key);
// the browser renders the QR from that text client-side and the server never
// persists or logs it. In client-keygen mode the browser generates its own
// keypair and submits only the public key.
func (s *Server) handleWireGuardProvision(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Name          string `json:"name"`
		Preset        string `json:"preset"`
		ServerKeygen  bool   `json:"server_keygen"`
		PeerPublicKey string `json:"public_key"`
		FixedIP       string `json:"fixed_ip"`
	}
	if !readJSON(w, r, &b) {
		return
	}
	preset := wireguard.FirewallPreset(strings.TrimSpace(b.Preset))
	if !preset.Valid() {
		writeErr(w, errInvalidPreset)
		return
	}
	res, err := s.Engine.ProvisionWireGuardPeer(
		strings.TrimSpace(b.Name), preset, b.ServerKeygen,
		strings.TrimSpace(b.PeerPublicKey), strings.TrimSpace(b.FixedIP))
	if err != nil {
		writeErr(w, err)
		return
	}
	// The response carries the one-shot client config only in server-keygen
	// mode. It is returned to the browser and dropped here; nothing persists it.
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"device":          res.Device,
		"peer_public_key": res.PeerPublicKey,
		"assigned_ip":     res.AssignedIP,
		"preset":          string(res.Preset),
		"client_config":   res.ClientConfig, // "" unless server-side keygen
	})
}

// handleWireGuardUpdate applies a full edit to an existing peer: endpoint,
// server-side AllowedIPs, and firewall preset. The keypair is preserved.
func (s *Server) handleWireGuardUpdate(w http.ResponseWriter, r *http.Request) {
	var b struct {
		PeerPublicKey string   `json:"public_key"`
		Endpoint      string   `json:"endpoint"`
		AllowedIPs    []string `json:"allowed_ips"`
		Keepalive     *int     `json:"keepalive_sec"` // nil = leave unchanged
		Preset        string   `json:"preset"`
	}
	if !readJSON(w, r, &b) {
		return
	}
	preset := wireguard.FirewallPreset(strings.TrimSpace(b.Preset))
	if !preset.Valid() {
		writeErr(w, errInvalidPreset)
		return
	}
	keepalive := -1 // leave unchanged unless supplied
	if b.Keepalive != nil {
		keepalive = *b.Keepalive
	}
	if err := s.Engine.UpdateWireGuardPeer(
		strings.TrimSpace(b.PeerPublicKey), strings.TrimSpace(b.Endpoint), b.AllowedIPs, keepalive, preset); err != nil {
		writeErr(w, err)
		return
	}
	writeOK(w)
}

// handleWireGuardNetplanRender returns the netplan YAML for the wg interface
// without writing it. An optional private key is embedded in the render only and
// never persisted. Read-only preview.
func (s *Server) handleWireGuardNetplanRender(w http.ResponseWriter, r *http.Request) {
	var b struct {
		PrivateKey string `json:"private_key"`
	}
	if !readJSON(w, r, &b) {
		return
	}
	yaml, err := s.Engine.RenderWireGuardNetplan(strings.TrimSpace(b.PrivateKey))
	if err != nil {
		writeErr(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"netplan": yaml})
}

// handleWireGuardInterfaceCreate writes a netplan tunnel for a new wg device and
// applies it. Returns the server public key (private key stays in the 0600 file).
func (s *Server) handleWireGuardInterfaceCreate(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Device     string `json:"device"`
		Address    string `json:"address"`
		ListenPort int    `json:"listen_port"`
		PrivateKey string `json:"private_key"`
	}
	if !readJSON(w, r, &b) {
		return
	}
	pub, err := s.Engine.CreateWireGuardInterface(
		strings.TrimSpace(b.Device), strings.TrimSpace(b.Address), b.ListenPort, strings.TrimSpace(b.PrivateKey))
	if err != nil {
		writeErr(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"device": b.Device, "public_key": pub})
}

// handleWireGuardInterfaceDelete removes a Testudo-created wg interface.
func (s *Server) handleWireGuardInterfaceDelete(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Device string `json:"device"`
	}
	if !readJSON(w, r, &b) {
		return
	}
	if err := s.Engine.DeleteWireGuardInterface(strings.TrimSpace(b.Device)); err != nil {
		writeErr(w, err)
		return
	}
	writeOK(w)
}

// handleWireGuardInterfaceTune applies performance tweaks (MTU, txqueuelen,
// socket buffers) to a wg device. With "recommended": true it applies the
// one-click max-performance profile.
func (s *Server) handleWireGuardInterfaceTune(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Device        string `json:"device"`
		MTU           int    `json:"mtu"`
		TxQueueLen    int    `json:"txqueuelen"`
		SocketBuffers bool   `json:"socket_buffers"`
		Recommended   bool   `json:"recommended"`
	}
	if !readJSON(w, r, &b) {
		return
	}
	if strings.TrimSpace(b.Device) == "" {
		writeErr(w, wireguardError("device required"))
		return
	}
	p := engine.TuneParams{MTU: b.MTU, TxQueueLen: b.TxQueueLen, SocketBuffers: b.SocketBuffers}
	if b.Recommended {
		p = engine.RecommendedTune()
	}
	if err := s.Engine.TuneWireGuardInterface(strings.TrimSpace(b.Device), p); err != nil {
		writeErr(w, err)
		return
	}
	writeOK(w)
}

// handleWireGuardInterfaceName sets a human label for a wg device (SQLite).
func (s *Server) handleWireGuardInterfaceName(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Device string `json:"device"`
		Name   string `json:"name"`
	}
	if !readJSON(w, r, &b) {
		return
	}
	if strings.TrimSpace(b.Device) == "" {
		writeErr(w, wireguardError("device required"))
		return
	}
	if err := s.Engine.SetWireGuardInterfaceName(strings.TrimSpace(b.Device), strings.TrimSpace(b.Name)); err != nil {
		writeErr(w, err)
		return
	}
	writeOK(w)
}

// handleWireGuardInterfaceRestart bounces the wg link (down/up).
func (s *Server) handleWireGuardInterfaceRestart(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Device string `json:"device"`
	}
	if !readJSON(w, r, &b) {
		return
	}
	if strings.TrimSpace(b.Device) == "" {
		writeErr(w, wireguardError("device required"))
		return
	}
	if err := s.Engine.RestartWireGuardInterface(strings.TrimSpace(b.Device)); err != nil {
		writeErr(w, err)
		return
	}
	writeOK(w)
}

// handleWireGuardNetplanList returns every netplan file under /etc/netplan for
// viewing/editing. Content may contain interface private keys, so this is an
// authenticated operator action; it is never logged.
func (s *Server) handleWireGuardNetplanList(w http.ResponseWriter, r *http.Request) {
	files, err := s.Engine.ListNetplan()
	if err != nil {
		writeErr(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"files": files})
}

// handleWireGuardNetplanSave writes edited content to a netplan file (write-gated;
// path validated under /etc/netplan by netops).
func (s *Server) handleWireGuardNetplanSave(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Path    string `json:"path"`
		Content string `json:"content"`
	}
	if !readJSON(w, r, &b) {
		return
	}
	if err := s.Engine.SaveNetplan(strings.TrimSpace(b.Path), b.Content); err != nil {
		writeErr(w, err)
		return
	}
	writeOK(w)
}

// handleWireGuardNetplanApply runs `netplan apply` (write-gated).
func (s *Server) handleWireGuardNetplanApply(w http.ResponseWriter, r *http.Request) {
	var b struct{}
	if !readJSON(w, r, &b) {
		return
	}
	if err := s.Engine.ApplyNetplan(); err != nil {
		writeErr(w, err)
		return
	}
	writeOK(w)
}

// handleWireGuardNetplanSaveApply writes edited content and applies it as one
// transaction with backup + validate + rollback (§2). Write-gated.
func (s *Server) handleWireGuardNetplanSaveApply(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Path    string `json:"path"`
		Content string `json:"content"`
	}
	if !readJSON(w, r, &b) {
		return
	}
	if err := s.Engine.SafeApplyNetplan(strings.TrimSpace(b.Path), b.Content); err != nil {
		writeErr(w, err)
		return
	}
	writeOK(w)
}

// handleWireGuardNetplanWrite renders and writes the wg-interface netplan file
// (write-gated). The operator applies it with `sudo netplan apply`.
func (s *Server) handleWireGuardNetplanWrite(w http.ResponseWriter, r *http.Request) {
	var b struct {
		PrivateKey string `json:"private_key"`
	}
	if !readJSON(w, r, &b) {
		return
	}
	path, err := s.Engine.WriteWireGuardNetplan(strings.TrimSpace(b.PrivateKey))
	if err != nil {
		writeErr(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"path": path,
		"note": "run `sudo netplan apply` to bring the interface up",
	})
}

// handleWireGuardDeprovision removes a peer and every artifact provisioning
// created for it (peer, route, firewall rules, IP) - the reverse transaction (G5).
func (s *Server) handleWireGuardDeprovision(w http.ResponseWriter, r *http.Request) {
	var b struct {
		PeerPublicKey string `json:"public_key"`
	}
	if !readJSON(w, r, &b) {
		return
	}
	if err := s.Engine.DeprovisionWireGuardPeer(strings.TrimSpace(b.PeerPublicKey)); err != nil {
		writeErr(w, err)
		return
	}
	writeOK(w)
}

var errInvalidPreset = wireguardError("preset must be full / split / isolated")

type wireguardError string

func (e wireguardError) Error() string { return string(e) }
