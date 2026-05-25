package web

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/noahzmr/testudo/internal/discovery"
)

// handleDeviceScan runs an on-demand TCP scan against one host's
// connection-relevant ports (SSH/Telnet/RDP/VNC/HTTP/HTTPS family). The
// result is also recorded in the inventory so subsequent /api/snapshot
// reads pick it up.
func (s *Server) handleDeviceScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var b struct {
		IP string `json:"ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(b.IP) == "" {
		http.Error(w, "ip required", http.StatusBadRequest)
		return
	}
	scanner := &discovery.Scanner{Inventory: s.Engine.Inventory()}
	ctx, cancel := context.WithTimeout(r.Context(), 6*time.Second)
	defer cancel()
	res := scanner.ScanHost(ctx, b.IP)
	out := scanResponse{
		IP:        res.IP,
		OpenPorts: res.OpenPorts,
		Protocols: make([]string, 0, len(res.Protocols)),
	}
	for _, p := range res.Protocols {
		out.Protocols = append(out.Protocols, string(p))
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

type scanResponse struct {
	IP        string   `json:"ip"`
	OpenPorts []uint16 `json:"open_ports"`
	Protocols []string `json:"protocols"`
}

// handleConnect builds the launch URL for a host+protocol+port triple and
// 303-redirects the browser to it. The URL is taken from:
//
//  1. GuacamoleTemplate when set - operator-supplied pattern with
//     {host}, {port}, {proto} placeholders, e.g.
//     `https://guac.example.com/#/client/?host={host}&protocol={proto}&port={port}`
//  2. Otherwise, native URI scheme:
//     - http://host:port/ and https://host:port/ for the web protocols
//     - ssh://host:port, rdp://host:port, vnc://host:port for the rest
//     The browser hands these to the system's registered URL handler
//     (PuTTY / OpenSSH / mstsc / xfreerdp / TightVNC etc.).
//
// Either way Testudo acts as the *launchpad* - the user always clicks one
// thing in the device row, regardless of how the underlying session is
// brokered.
func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	host := strings.TrimSpace(q.Get("host"))
	proto := strings.ToLower(strings.TrimSpace(q.Get("proto")))
	port := strings.TrimSpace(q.Get("port"))
	if host == "" || proto == "" {
		http.Error(w, "host and proto required", http.StatusBadRequest)
		return
	}
	url := buildConnectURL(s.Engine.Settings().Snapshot().GuacamoleTemplate, host, proto, port)
	if url == "" {
		http.Error(w, "unsupported proto: "+proto, http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, url, http.StatusSeeOther)
}

// buildConnectURL prefers an operator-supplied Guacamole template; falls
// back to native URI schemes so the launchpad UX works out of the box.
func buildConnectURL(template, host, proto, port string) string {
	if t := strings.TrimSpace(template); t != "" {
		out := strings.ReplaceAll(t, "{host}", host)
		out = strings.ReplaceAll(out, "{proto}", proto)
		out = strings.ReplaceAll(out, "{port}", port)
		return out
	}
	switch proto {
	case "http":
		if port == "" || port == "80" {
			return "http://" + host + "/"
		}
		return fmt.Sprintf("http://%s:%s/", host, port)
	case "https":
		if port == "" || port == "443" {
			return "https://" + host + "/"
		}
		return fmt.Sprintf("https://%s:%s/", host, port)
	case "ssh":
		if port == "" || port == "22" {
			return "ssh://" + host
		}
		return fmt.Sprintf("ssh://%s:%s", host, port)
	case "rdp":
		if port == "" || port == "3389" {
			return "rdp://" + host
		}
		return fmt.Sprintf("rdp://%s:%s", host, port)
	case "vnc":
		if port == "" || port == "5900" {
			return "vnc://" + host
		}
		return fmt.Sprintf("vnc://%s:%s", host, port)
	case "telnet":
		if port == "" || port == "23" {
			return "telnet://" + host
		}
		return fmt.Sprintf("telnet://%s:%s", host, port)
	}
	return ""
}
