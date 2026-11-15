package confapi

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/noahzmr/testudo/internal/confstore"
	"github.com/noahzmr/testudo/internal/lbrender"
	"github.com/noahzmr/testudo/internal/model"
)

// CertMaker creates and stores certificate key material on the node. A
// private key goes into the node's secret store and nowhere else; the model
// and the answers carry the name of its entry.
type CertMaker interface {
	// IssueCertificate creates a key and a certificate for the names from
	// the internal certificate authority.
	IssueCertificate(names []string) (chainPEM, keyRef string, notAfter time.Time, err error)
	// ImportCertificateKey stores the private key of a certificate issued
	// elsewhere, after checking that it belongs to the certificate.
	ImportCertificateKey(chainPEM string, keyPEM []byte) (keyRef string, notAfter time.Time, err error)
	// CACertificate returns the internal authority's certificate in PEM.
	CACertificate() ([]byte, error)
}

var systemKind = func() model.KindInfo { info, _ := model.Lookup(string(model.KindCertificate)); return info }()

func (s *Server) certWrite(w http.ResponseWriter, r *http.Request) bool {
	if s.Certs == nil {
		fail(w, http.StatusServiceUnavailable, "unavailable", "certificates cannot be created on this node")
		return false
	}
	if area := Area(systemKind); !who(r).Can(area, "write") {
		fail(w, http.StatusForbidden, "forbidden", "needs "+area+":write")
		return false
	}
	return true
}

// pkiIssue issues a certificate from the internal authority and returns the
// fields of a certificate object. The object itself is created like any
// other, so it goes through review, apply and confirmation.
func (s *Server) pkiIssue(w http.ResponseWriter, r *http.Request) {
	if !s.certWrite(w, r) {
		return
	}
	var in struct {
		Domains []string `json:"domains"`
	}
	body, err := readBody(w, r, 1<<16)
	if err != nil || json.Unmarshal(body, &in) != nil || len(in.Domains) == 0 || len(in.Domains) > 100 {
		fail(w, http.StatusBadRequest, "bad_request", "give between 1 and 100 names in domains")
		return
	}
	// The model's own rule for the field decides which names are valid.
	if err := model.Validate(&model.Certificate{Meta: model.Meta{ID: confstore.NewID(), Name: "probe", Scope: model.ScopeGlobal}, Source: "internal_ca", Domains: in.Domains}); err != nil {
		fail(w, http.StatusUnprocessableEntity, "invalid", "a name in domains is not a host name")
		return
	}
	chain, ref, notAfter, err := s.Certs.IssueCertificate(in.Domains)
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal", "could not issue the certificate")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"source": "internal_ca", "domains": in.Domains, "chain_pem": chain, "key_ref": ref, "not_after": notAfter})
}

// pkiImport stores the private key of a certificate issued elsewhere. The
// key is not echoed back and never enters the model.
func (s *Server) pkiImport(w http.ResponseWriter, r *http.Request) {
	if !s.certWrite(w, r) {
		return
	}
	var in struct {
		ChainPEM string `json:"chain_pem"`
		KeyPEM   string `json:"key_pem"`
	}
	body, err := readBody(w, r, 1<<18)
	if err != nil || json.Unmarshal(body, &in) != nil || in.ChainPEM == "" || in.KeyPEM == "" {
		fail(w, http.StatusBadRequest, "bad_request", "give chain_pem and key_pem")
		return
	}
	ref, notAfter, err := s.Certs.ImportCertificateKey(in.ChainPEM, []byte(in.KeyPEM))
	if err != nil {
		// The reason names what is wrong with the pair, never its content.
		fail(w, http.StatusUnprocessableEntity, "invalid", err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"source": "import", "chain_pem": in.ChainPEM, "key_ref": ref, "not_after": notAfter})
}

// pkiCA serves the internal authority's certificate, for clients to trust.
func (s *Server) pkiCA(w http.ResponseWriter, r *http.Request) {
	if s.Certs == nil {
		fail(w, http.StatusServiceUnavailable, "unavailable", "there is no certificate authority on this node")
		return
	}
	if area := Area(systemKind); !who(r).Can(area, "read") {
		fail(w, http.StatusForbidden, "forbidden", "needs "+area+":read")
		return
	}
	pemBytes, err := s.Certs.CACertificate()
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal", "could not read the authority's certificate")
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="testudo-ca.pem"`)
	w.Write(pemBytes)
}

// lbFirewallHints lists, per load-balancer service, whether a filter rule
// lets clients in and, if not, the rule that would. Nothing is created.
func (s *Server) lbFirewallHints(w http.ResponseWriter, r *http.Request) {
	if !who(r).Can("loadbalancer", "read") || !who(r).Can("firewall", "read") {
		fail(w, http.StatusForbidden, "forbidden", "needs loadbalancer:read and firewall:read")
		return
	}
	hints := lbrender.FirewallHints(s.Store.Current())
	if hints == nil {
		hints = []lbrender.Hint{}
	}
	writeJSON(w, http.StatusOK, hints)
}
