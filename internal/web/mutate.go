package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/noahzmr/testudo/internal/capture"
	"github.com/noahzmr/testudo/internal/netops"
)

// readJSON binds the request body to v and writes a 400 on failure.
func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return false
	}
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return false
	}
	return true
}

// writeOK is the standard no-content success response.
func writeOK(w http.ResponseWriter) {
	w.WriteHeader(http.StatusNoContent)
}

// writeErr surfaces a domain error as 422 Unprocessable Entity. Reserved
// for "the request was structurally fine but the kernel / netops layer
// refused it" — most operator-relevant errors land here.
func writeErr(w http.ResponseWriter, err error) {
	http.Error(w, err.Error(), http.StatusUnprocessableEntity)
}

// ---- Capture control ------------------------------------------------

func (s *Server) handleCaptureStart(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Ifaces []string `json:"ifaces"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	if err := s.Engine.StartCapture(body.Ifaces); err != nil {
		writeErr(w, err)
		return
	}
	writeOK(w)
}

func (s *Server) handleCaptureStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.Engine.StopCapture()
	writeOK(w)
}

func (s *Server) handleCaptureClear(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.Engine.Flows().Reset()
	writeOK(w)
}

// ---- Interface controls --------------------------------------------

func (s *Server) handleIfaceUp(w http.ResponseWriter, r *http.Request) {
	var b struct{ Name string `json:"name"` }
	if !readJSON(w, r, &b) {
		return
	}
	if err := s.Engine.Netops().SetIfaceUp(b.Name); err != nil {
		writeErr(w, err)
		return
	}
	writeOK(w)
}

func (s *Server) handleIfaceDown(w http.ResponseWriter, r *http.Request) {
	var b struct{ Name string `json:"name"` }
	if !readJSON(w, r, &b) {
		return
	}
	if err := s.Engine.Netops().SetIfaceDown(b.Name); err != nil {
		writeErr(w, err)
		return
	}
	writeOK(w)
}

func (s *Server) handleIfaceAddAddr(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Name string `json:"name"`
		CIDR string `json:"cidr"`
	}
	if !readJSON(w, r, &b) {
		return
	}
	if err := s.Engine.Netops().AddAddr(b.Name, b.CIDR); err != nil {
		writeErr(w, err)
		return
	}
	writeOK(w)
}

func (s *Server) handleIfaceDelAddr(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Name string `json:"name"`
		CIDR string `json:"cidr"`
	}
	if !readJSON(w, r, &b) {
		return
	}
	if err := s.Engine.Netops().DelAddr(b.Name, b.CIDR); err != nil {
		writeErr(w, err)
		return
	}
	writeOK(w)
}

func (s *Server) handleIfaceMTU(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Name string `json:"name"`
		MTU  int    `json:"mtu"`
	}
	if !readJSON(w, r, &b) {
		return
	}
	if err := s.Engine.Netops().SetMTU(b.Name, b.MTU); err != nil {
		writeErr(w, err)
		return
	}
	writeOK(w)
}

func (s *Server) handleIfaceDHCP(w http.ResponseWriter, r *http.Request) {
	var b struct{ Name string `json:"name"` }
	if !readJSON(w, r, &b) {
		return
	}
	if err := s.Engine.Netops().SetIfaceDHCP(b.Name); err != nil {
		writeErr(w, err)
		return
	}
	writeOK(w)
}

func (s *Server) handleIfaceStatic(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Name string `json:"name"`
		CIDR string `json:"cidr"`
	}
	if !readJSON(w, r, &b) {
		return
	}
	if err := s.Engine.Netops().SetIfaceStatic(b.Name, b.CIDR); err != nil {
		writeErr(w, err)
		return
	}
	writeOK(w)
}

// ---- Route controls --------------------------------------------------

func (s *Server) handleRouteAdd(w http.ResponseWriter, r *http.Request) {
	var b struct {
		CIDR    string `json:"cidr"`
		Gateway string `json:"gateway"`
		Iface   string `json:"iface"`
	}
	if !readJSON(w, r, &b) {
		return
	}
	if err := s.Engine.Netops().AddRoute(b.CIDR, b.Gateway, b.Iface); err != nil {
		writeErr(w, err)
		return
	}
	writeOK(w)
}

func (s *Server) handleRouteDel(w http.ResponseWriter, r *http.Request) {
	var b struct{ CIDR string `json:"cidr"` }
	if !readJSON(w, r, &b) {
		return
	}
	if err := s.Engine.Netops().DelRoute(b.CIDR); err != nil {
		writeErr(w, err)
		return
	}
	writeOK(w)
}

// ---- Firewall controls -----------------------------------------------

func (s *Server) handleFirewallAdd(w http.ResponseWriter, r *http.Request) {
	var b netops.FilterRule
	if !readJSON(w, r, &b) {
		return
	}
	if err := s.Engine.Netops().AddFilterRule(b); err != nil {
		writeErr(w, err)
		return
	}
	writeOK(w)
}

func (s *Server) handleFirewallDel(w http.ResponseWriter, r *http.Request) {
	var b netops.FilterRule
	if !readJSON(w, r, &b) {
		return
	}
	if err := s.Engine.Netops().DelFilterRule(b); err != nil {
		writeErr(w, err)
		return
	}
	writeOK(w)
}

// ---- NAT controls ----------------------------------------------------

func (s *Server) handleNATAdd(w http.ResponseWriter, r *http.Request) {
	var b netops.PortForward
	if !readJSON(w, r, &b) {
		return
	}
	if err := s.Engine.Netops().AddPortForward(b); err != nil {
		writeErr(w, err)
		return
	}
	writeOK(w)
}

func (s *Server) handleNATDel(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Proto   string `json:"proto"`
		WANPort uint16 `json:"wan_port"`
	}
	if !readJSON(w, r, &b) {
		return
	}
	if err := s.Engine.Netops().DelPortForward(b.Proto, b.WANPort); err != nil {
		writeErr(w, err)
		return
	}
	writeOK(w)
}

// ---- TCPDump controls ------------------------------------------------

func (s *Server) handleTCPDumpStart(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Iface       string `json:"iface"`
		Name        string `json:"name"`
		Filter      string `json:"filter"`
		MaxSizeMB   int    `json:"max_size_mb"`
		DurationSec int    `json:"duration_sec"`
		// Filter wizard fields — assembled into BPF if Filter is empty.
		Proto   string `json:"proto"`
		SrcHost string `json:"src_host"`
		DstHost string `json:"dst_host"`
		SrcPort string `json:"src_port"`
		DstPort string `json:"dst_port"`
		Raw     string `json:"raw_filter"`
	}
	if !readJSON(w, r, &b) {
		return
	}
	bpf := strings.TrimSpace(b.Filter)
	if bpf == "" {
		bpf = capture.FilterSpec{
			Proto:     b.Proto,
			SrcHost:   b.SrcHost,
			DstHost:   b.DstHost,
			SrcPort:   b.SrcPort,
			DstPort:   b.DstPort,
			RawAppend: b.Raw,
		}.Build()
	}
	job, err := s.Engine.TCPDump().Start(b.Iface, b.Name, bpf, b.MaxSizeMB,
		time.Duration(b.DurationSec)*time.Second)
	if err != nil {
		writeErr(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"id": job.ID})
}

func (s *Server) handleTCPDumpStop(w http.ResponseWriter, r *http.Request) {
	var b struct{ ID string `json:"id"` }
	if !readJSON(w, r, &b) {
		return
	}
	if err := s.Engine.TCPDump().Stop(b.ID); err != nil {
		writeErr(w, err)
		return
	}
	writeOK(w)
}

func (s *Server) handleTCPDumpRemove(w http.ResponseWriter, r *http.Request) {
	var b struct{ ID string `json:"id"` }
	if !readJSON(w, r, &b) {
		return
	}
	if err := s.Engine.TCPDump().Remove(b.ID); err != nil {
		writeErr(w, err)
		return
	}
	writeOK(w)
}

// ---- Common write-guard helper --------------------------------------

// requireNetops short-circuits the request when the engine has no live
// netops.Writer (e.g. the binary lacks CAP_NET_ADMIN). Saves every handler
// repeating the same nil-check.
func (s *Server) requireNetops(w http.ResponseWriter, next http.HandlerFunc) http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		if s.Engine.Netops() == nil {
			writeErr(w, fmt.Errorf("netops not available — process lacks CAP_NET_ADMIN"))
			return
		}
		next(rw, r)
	}
}
