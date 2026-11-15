package confapi

import (
	"net/http"

	"github.com/noahzmr/testudo/internal/model"
	"github.com/noahzmr/testudo/internal/wgrender"
)

// KeyMaker creates WireGuard key material on the node. Private keys of
// tunnels and preshared keys go into the node's secret store; the model and
// the answers only carry the names of the entries.
type KeyMaker interface {
	// NewTunnelKey creates and stores a private key and returns the name of
	// its entry and the public key.
	NewTunnelKey() (ref, publicKey string, err error)
	// NewPresharedKey creates and stores a preshared key. The key itself is
	// returned this one time, for the client's configuration.
	NewPresharedKey() (ref, key string, err error)
	// NewClientKeypair creates a key pair for a client device and stores
	// nothing: it is for browsers that cannot generate one themselves.
	NewClientKeypair() (privateKey, publicKey string, err error)
}

func (s *Server) vpnWrite(w http.ResponseWriter, r *http.Request) bool {
	if s.Keys == nil {
		fail(w, http.StatusServiceUnavailable, "unavailable", "key generation is not available on this node")
		return false
	}
	if !who(r).Can("vpn", "write") {
		fail(w, http.StatusForbidden, "forbidden", "needs vpn:write")
		return false
	}
	return true
}

func (s *Server) wgTunnelKey(w http.ResponseWriter, r *http.Request) {
	if !s.vpnWrite(w, r) {
		return
	}
	ref, pub, err := s.Keys.NewTunnelKey()
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal", "could not create the key")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"key_ref": ref, "public_key": pub})
}

func (s *Server) wgPresharedKey(w http.ResponseWriter, r *http.Request) {
	if !s.vpnWrite(w, r) {
		return
	}
	ref, key, err := s.Keys.NewPresharedKey()
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal", "could not create the key")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"preshared_ref": ref, "preshared_key": key})
}

func (s *Server) wgClientKeypair(w http.ResponseWriter, r *http.Request) {
	if !s.vpnWrite(w, r) {
		return
	}
	priv, pub, err := s.Keys.NewClientKeypair()
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal", "could not create the key pair")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"private_key": priv, "public_key": pub})
}

// wgClientConfig returns a peer's client configuration with placeholders
// where its two secrets go. The server does not have the client's private
// key, and it shows a preshared key only when it creates it.
func (s *Server) wgClientConfig(w http.ResponseWriter, r *http.Request) {
	if !who(r).Can("vpn", "read") {
		fail(w, http.StatusForbidden, "forbidden", "needs vpn:read")
		return
	}
	conf, err := wgrender.ClientConfig(s.Store.Current(), r.PathValue("id"))
	if err != nil {
		if _, ok := s.Store.Current().Get(model.KindWGPeer, r.PathValue("id")); !ok {
			fail(w, http.StatusNotFound, "not_found", "no such peer")
			return
		}
		fail(w, http.StatusUnprocessableEntity, "incomplete", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"config": conf,
		"private_key_placeholder": wgrender.PrivateKeyPlaceholder, "preshared_key_placeholder": wgrender.PresharedKeyPlaceholder})
}
