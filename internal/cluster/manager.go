package cluster

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/noahzmr/testudo/internal/confstore"
	"github.com/noahzmr/testudo/internal/pki"
	"github.com/noahzmr/testudo/internal/secrets"
)

// Entries of a member's own secret store that belong to the cluster. The
// first three are this member's alone and are never replicated; the
// authority's entries are, sealed, so that whichever member leads can admit
// a new one.
const (
	entryNodeKey  = "cluster-node-key"
	entryNodeCert = "cluster-node-cert" // this member's certificate followed by the authority's
	entryKey      = "cluster-key"
	caName        = "cluster"
	entryCAKey    = caName + "-ca-key"
	entryCACert   = caName + "-ca-cert"

	// CertValidity is how long a member's certificate is good for. Members
	// renew at two thirds of it.
	CertValidity = 90 * 24 * time.Hour
	tokenPrefix  = "tdj1."
	// SystemActor is the actor of records the program writes by itself.
	SystemActor = "system"
)

// Config configures a member's place in a cluster.
type Config struct {
	// ID identifies the member; Name is what people call it.
	ID, Name string
	// Dir holds the member's cluster files.
	Dir string
	// RaftBind and APIBind are the listen addresses of the consensus
	// transport and the member API. Neither should be reachable from
	// outside: bind them to the address of the site mesh.
	RaftBind, APIBind string
	// RaftAdvertise and APIAdvertise are what other members connect to
	// (default: the bind addresses).
	RaftAdvertise, APIAdvertise string

	Store   *confstore.Store
	Secrets secrets.Store
	Build   string

	// Forwarded serves a console API request another member passed on
	// because this one leads. identity is the caller as the other member
	// authenticated them, in the web layer's own encoding.
	Forwarded func(w http.ResponseWriter, r *http.Request, identity string)
	// Changed is called when the replicated state or the leader changed.
	Changed func()
	// MeshKey returns the public key of this member's fabric tunnels, or
	// "" when it has none.
	MeshKey func() string
	// Timing overrides for tests and unusual links (zero: the defaults).
	Heartbeat, Election, LeaderLease time.Duration
	LogOutput                        io.Writer
}

// Manager is a member's handle on its cluster: the consensus node, the
// member API, and the certificates.
type Manager struct {
	cfg   Config
	local secrets.Store // never replicated

	mu   sync.RWMutex
	node *Node
	srv  *http.Server
	stop chan struct{}
}

type memberFile struct {
	ID   string `json:"id"`
	Raft string `json:"raft"`
	API  string `json:"api"`
}

// NewManager prepares a member. Start opens it if it already belongs to a
// cluster; Init and Join make it one.
func NewManager(cfg Config) (*Manager, error) {
	if cfg.ID == "" || cfg.Dir == "" || cfg.RaftBind == "" || cfg.APIBind == "" || cfg.Store == nil {
		return nil, errors.New("cluster: id, directory, both bind addresses and the store are required")
	}
	if cfg.RaftAdvertise == "" {
		cfg.RaftAdvertise = cfg.RaftBind
	}
	if cfg.APIAdvertise == "" {
		cfg.APIAdvertise = cfg.APIBind
	}
	return &Manager{cfg: cfg, local: cfg.Secrets.Local()}, nil
}

func (m *Manager) memberPath() string { return filepath.Join(m.cfg.Dir, "member.json") }

// Member reports whether this node belongs to a cluster.
func (m *Manager) Member() bool {
	_, err := os.Stat(m.memberPath())
	return err == nil
}

// Node returns the consensus node, or nil when the member is not open.
func (m *Manager) Node() *Node {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.node
}

func (m *Manager) key() []byte {
	k, err := m.local.Get(entryKey)
	if err != nil || len(k) != KeySize {
		return nil
	}
	return k
}

// ---- certificates -------------------------------------------------------

func (m *Manager) caPool() (*x509.CertPool, error) {
	chain, err := m.local.Get(entryNodeCert)
	if err != nil {
		return nil, err
	}
	// The authority's certificate is the last one in the member's chain.
	var last *x509.Certificate
	for rest := chain; ; {
		var b *pem.Block
		if b, rest = pem.Decode(rest); b == nil {
			break
		}
		if c, err := x509.ParseCertificate(b.Bytes); err == nil {
			last = c
		}
	}
	if last == nil || !last.IsCA {
		return nil, errors.New("cluster: this member has no authority certificate")
	}
	pool := x509.NewCertPool()
	pool.AddCert(last)
	return pool, nil
}

func (m *Manager) certificate() (*tls.Certificate, error) {
	chain, err := m.local.Get(entryNodeCert)
	if err != nil {
		return nil, err
	}
	key, err := m.local.Get(entryNodeKey)
	if err != nil {
		return nil, err
	}
	c, err := tls.X509KeyPair(chain, key)
	return &c, err
}

// verifyPeer accepts a certificate the cluster's authority issued for a
// member and that has not been revoked. Names and addresses are not
// compared: members move, and what identifies one is the authority's
// signature over its id.
func (m *Manager) verifyPeer(raw [][]byte, usage x509.ExtKeyUsage) (*x509.Certificate, error) {
	if len(raw) == 0 {
		return nil, errors.New("cluster: no certificate")
	}
	leaf, err := x509.ParseCertificate(raw[0])
	if err != nil {
		return nil, err
	}
	pool, err := m.caPool()
	if err != nil {
		return nil, err
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{usage}}); err != nil {
		return nil, fmt.Errorf("cluster: certificate not issued by this cluster: %w", err)
	}
	if n := m.Node(); n != nil {
		if _, revoked := n.State().Revoked[leaf.SerialNumber.Text(16)]; revoked {
			return nil, fmt.Errorf("cluster: the certificate of %s was revoked", leaf.Subject.CommonName)
		}
	}
	return leaf, nil
}

// serverTLS is for listeners. With requireClient every peer has to be a
// member; without, a peer may come without a certificate (a node that
// wants to join) and the handler decides.
func (m *Manager) serverTLS(requireClient bool) *tls.Config {
	auth := tls.RequestClientCert
	if requireClient {
		auth = tls.RequireAnyClientCert
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: auth,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return m.certificate() },
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 && !requireClient {
				return nil
			}
			_, err := m.verifyPeer(raw, x509.ExtKeyUsageClientAuth)
			return err
		}}
}

func (m *Manager) clientTLS() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS13,
		// Verification is done below, against the cluster's authority and
		// its revocations, without comparing host names.
		InsecureSkipVerify:   true,
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return m.certificate() },
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			_, err := m.verifyPeer(raw, x509.ExtKeyUsageServerAuth)
			return err
		}}
}

func hostOf(addr string) string {
	h, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return h
}

// ---- lifecycle ----------------------------------------------------------

// Start opens the member if it belongs to a cluster. It is not an error
// when it does not.
func (m *Manager) Start() error {
	if !m.Member() {
		return nil
	}
	return m.open()
}

func (m *Manager) open() error {
	node, err := Open(Options{ID: m.cfg.ID, Dir: filepath.Join(m.cfg.Dir, "raft"), Bind: m.cfg.RaftBind, Advertise: m.cfg.RaftAdvertise,
		Store: m.cfg.Store, Secrets: m.cfg.Secrets, Key: m.key, ServerTLS: m.serverTLS(true), ClientTLS: m.clientTLS(),
		Heartbeat: m.cfg.Heartbeat, Election: m.cfg.Election, LeaderLease: m.cfg.LeaderLease,
		Changed: m.cfg.Changed, LogOutput: m.cfg.LogOutput})
	if err != nil {
		return err
	}
	ln, err := tls.Listen("tcp", m.cfg.APIBind, m.serverTLS(false))
	if err != nil {
		node.Shutdown()
		return fmt.Errorf("cluster: member API: %w", err)
	}
	srv := &http.Server{Handler: m.routes(), ReadHeaderTimeout: 10 * time.Second, ErrorLog: nil}
	stop := make(chan struct{})
	m.mu.Lock()
	m.node, m.srv, m.stop = node, srv, stop
	m.mu.Unlock()
	m.cfg.Store.SetReplicator(node)
	go srv.Serve(ln)
	go m.housekeeping(stop)
	return nil
}

// Close stops the member's part in the cluster.
func (m *Manager) Close() {
	m.mu.Lock()
	node, srv, stop := m.node, m.srv, m.stop
	m.node, m.srv, m.stop = nil, nil, nil
	m.mu.Unlock()
	if stop != nil {
		close(stop)
	}
	if srv != nil {
		srv.Close()
	}
	if node != nil {
		node.Shutdown()
	}
}

func (m *Manager) writeMember() error {
	if err := os.MkdirAll(m.cfg.Dir, 0o700); err != nil {
		return err
	}
	data, _ := json.Marshal(memberFile{ID: m.cfg.ID, Raft: m.cfg.RaftAdvertise, API: m.cfg.APIAdvertise})
	return os.WriteFile(m.memberPath(), data, 0o600)
}

// Init makes this node the first member of a new cluster: it creates the
// cluster's key and authority, a certificate for itself, and a consensus
// group of one. A model the node already has becomes the cluster's.
func (m *Manager) Init(ctx context.Context) error {
	if m.Member() {
		return errors.New("cluster: this node already belongs to a cluster")
	}
	key, err := NewKey()
	if err != nil {
		return err
	}
	if err := m.local.Put(entryKey, key); err != nil {
		return err
	}
	ca := pki.CA{Secrets: m.local, Name: caName}
	keyPEM, csr, err := pki.NewRequest(m.cfg.ID, []string{hostOf(m.cfg.RaftAdvertise), hostOf(m.cfg.APIAdvertise)})
	if err != nil {
		return err
	}
	chain, serial, err := ca.SignRequest(csr, m.cfg.ID, CertValidity)
	if err != nil {
		return err
	}
	if err := m.local.Put(entryNodeKey, keyPEM); err != nil {
		return err
	}
	if err := m.local.Put(entryNodeCert, chain); err != nil {
		return err
	}
	if err := m.writeMember(); err != nil {
		return err
	}
	if err := m.open(); err != nil {
		os.Remove(m.memberPath())
		return err
	}
	node := m.Node()
	if err := node.Bootstrap(ctx); err != nil {
		return err
	}
	// The authority goes to every later member, sealed.
	for _, name := range []string{entryCAKey, entryCACert} {
		v, err := m.local.Get(name)
		if err != nil {
			return err
		}
		if err := node.PutSecret(name, v, false); err != nil {
			return err
		}
	}
	return node.Announce(Member{Name: m.cfg.Name, Build: m.cfg.Build, API: m.cfg.APIAdvertise, Serial: serial, Voter: true})
}

// ---- join tokens --------------------------------------------------------

type tokenBody struct {
	API    string `json:"a"` // member API to contact
	CA     string `json:"f"` // SHA-256 of the authority's certificate
	Secret string `json:"s"`
}

func tokenHash(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// NewToken issues a join token, valid once and until ttl has passed. The
// token names where to connect and which authority to expect there, so the
// joining node can tell the cluster from an impostor before it sends
// anything.
func (m *Manager) NewToken(ttl time.Duration, voter bool) (string, error) {
	node := m.Node()
	if node == nil {
		return "", errors.New("cluster: this node does not belong to a cluster")
	}
	caPEM, err := m.local.Get(entryCACert)
	if err != nil {
		return "", fmt.Errorf("cluster: the authority is not on this member: %w", err)
	}
	block, _ := pem.Decode(caPEM)
	if block == nil {
		return "", errors.New("cluster: unreadable authority certificate")
	}
	sum := sha256.Sum256(block.Bytes)
	secret := randomString()
	c, err := command(CmdToken, "", Token{Hash: tokenHash(secret), Expires: time.Now().Add(ttl).UTC(), Voter: voter})
	if err != nil {
		return "", err
	}
	if err := m.propose(context.Background(), c); err != nil {
		return "", err
	}
	body, _ := json.Marshal(tokenBody{API: m.cfg.APIAdvertise, CA: hex.EncodeToString(sum[:]), Secret: secret})
	return tokenPrefix + base64.RawURLEncoding.EncodeToString(body), nil
}

func randomString() string {
	k, _ := NewKey()
	return base64.RawURLEncoding.EncodeToString(k)
}

func parseToken(token string) (tokenBody, error) {
	var t tokenBody
	raw, ok := strings.CutPrefix(strings.TrimSpace(token), tokenPrefix)
	if !ok {
		return t, errors.New("cluster: this is not a join token")
	}
	data, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil || json.Unmarshal(data, &t) != nil || t.API == "" || t.CA == "" || t.Secret == "" {
		return t, errors.New("cluster: the join token is damaged")
	}
	return t, nil
}

type joinRequest struct {
	Token string `json:"token"`
	ID    string `json:"id"`
	Name  string `json:"name"`
	Build string `json:"build"`
	Raft  string `json:"raft"`
	API   string `json:"api"`
	CSR   []byte `json:"csr"`
}

type joinResponse struct {
	Chain []byte `json:"chain"` // the member's certificate and the authority's
	Key   []byte `json:"key"`   // the cluster key
}

// Join makes this node a member of the cluster the token is for. The node
// must not have a model of its own; the cluster's replaces nothing.
func (m *Manager) Join(ctx context.Context, token string) error {
	if m.Member() {
		return errors.New("cluster: this node already belongs to a cluster")
	}
	// A node joins empty. What the program itself put into a fresh store
	// (the built-in roles) does not count and is replaced by the cluster's.
	pristine := false
	if m.cfg.Store.Current().Index() != 0 {
		var err error
		if pristine, err = m.cfg.Store.OnlyBy(SystemActor); err != nil || !pristine {
			return errors.New("cluster: this node has a configuration of its own; a node joins empty")
		}
	}
	t, err := parseToken(token)
	if err != nil {
		return err
	}
	keyPEM, csr, err := pki.NewRequest(m.cfg.ID, []string{hostOf(m.cfg.RaftAdvertise), hostOf(m.cfg.APIAdvertise)})
	if err != nil {
		return err
	}
	// Before this node has the authority's certificate it recognises the
	// cluster by the fingerprint in the token.
	pinned := &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true,
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) < 2 {
				return errors.New("cluster: the other side did not present its authority")
			}
			ca, err := x509.ParseCertificate(raw[len(raw)-1])
			if err != nil {
				return err
			}
			sum := sha256.Sum256(ca.Raw)
			if hex.EncodeToString(sum[:]) != t.CA {
				return errors.New("cluster: the other side is not the cluster this token is for")
			}
			leaf, err := x509.ParseCertificate(raw[0])
			if err != nil {
				return err
			}
			pool := x509.NewCertPool()
			pool.AddCert(ca)
			_, err = leaf.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
			return err
		}}
	hc := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: pinned}}
	req := joinRequest{Token: t.Secret, ID: m.cfg.ID, Name: m.cfg.Name, Build: m.cfg.Build, Raft: m.cfg.RaftAdvertise, API: m.cfg.APIAdvertise, CSR: csr}
	var res joinResponse
	api := t.API
	for hop := 0; ; hop++ {
		next, err := post(ctx, hc, api, "/cluster/v1/join", req, &res)
		if err != nil {
			return err
		}
		if next == "" {
			break
		}
		if hop == 3 {
			return ErrNoQuorum
		}
		api = next // that member does not lead; this one does
	}
	if len(res.Key) != KeySize {
		return errors.New("cluster: the answer carries no cluster key")
	}
	if pristine {
		if err := m.cfg.Store.Reset(); err != nil {
			return err
		}
	}
	for name, v := range map[string][]byte{entryKey: res.Key, entryNodeKey: keyPEM, entryNodeCert: res.Chain} {
		if err := m.local.Put(name, v); err != nil {
			return err
		}
	}
	if err := m.writeMember(); err != nil {
		return err
	}
	return m.open()
}

// post sends a JSON request to a member's API. A member that does not lead
// answers with the leader's address, which is returned as next.
func post(ctx context.Context, hc *http.Client, api, path string, in, out any) (next string, err error) {
	body, _ := json.Marshal(in)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+api+path, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := hc.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(res.Body, 4<<20))
	switch {
	case res.StatusCode == http.StatusMisdirectedRequest:
		if next = res.Header.Get("X-Testudo-Leader"); next == "" {
			return "", ErrNoQuorum
		}
		return next, nil
	case res.StatusCode/100 != 2:
		return "", fmt.Errorf("cluster: %s: %s", path, strings.TrimSpace(string(data)))
	}
	if out != nil && len(data) > 0 {
		return "", json.Unmarshal(data, out)
	}
	return "", nil
}

// ---- talking to the leader ----------------------------------------------

func (m *Manager) client() *http.Client {
	return &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: m.clientTLS()}}
}

// LeaderAPI returns the member API address of the leader, or "".
func (m *Manager) LeaderAPI() string {
	node := m.Node()
	if node == nil {
		return ""
	}
	id, _ := node.Leader()
	if id == "" {
		return ""
	}
	return node.State().Members[id].API
}

// send posts to the leader, following it when it moves.
func (m *Manager) send(ctx context.Context, path string, in, out any) error {
	api := m.LeaderAPI()
	if api == "" {
		return ErrNoQuorum
	}
	hc := m.client()
	for hop := 0; hop < 3; hop++ {
		next, err := post(ctx, hc, api, path, in, out)
		if err != nil || next == "" {
			return err
		}
		api = next
	}
	return ErrNoQuorum
}

// propose gets a command agreed on: directly when this member leads,
// through the leader otherwise.
func (m *Manager) propose(ctx context.Context, c Command) error {
	node := m.Node()
	if node == nil {
		return errors.New("cluster: this node does not belong to a cluster")
	}
	if node.IsLeader() {
		return node.Propose(ctx, c)
	}
	return m.send(ctx, "/cluster/v1/propose", c, nil)
}

// SendResult delivers an apply report to the leader.
func (m *Manager) SendResult(r Result) error {
	c, err := command(CmdResult, "", r)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return m.propose(ctx, c)
}

// PutSecret replicates a secret from any member.
func (m *Manager) PutSecret(name string, value []byte, remove bool) error {
	node := m.Node()
	if node == nil {
		return errors.New("cluster: this node does not belong to a cluster")
	}
	if node.IsLeader() {
		return node.PutSecret(name, value, remove)
	}
	op := SecretOp{Name: name, Remove: remove}
	if !remove {
		sealed, err := seal(m.key(), name, value)
		if err != nil {
			return err
		}
		op.Sealed = sealed
	}
	c, err := command(CmdSecret, "", op)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return m.propose(ctx, c)
}

// Forward passes a console API request on to the leader and writes the
// leader's answer. identity travels with it; the leader trusts it because
// only a member can reach the endpoint.
func (m *Manager) Forward(w http.ResponseWriter, r *http.Request, identity string) {
	api := m.LeaderAPI()
	if api == "" {
		http.Error(w, "the cluster has no leader: this member is read-only until it can reach a majority", http.StatusServiceUnavailable)
		return
	}
	proxy := &httputil.ReverseProxy{
		Transport: &http.Transport{TLSClientConfig: m.clientTLS()},
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(&url.URL{Scheme: "https", Host: api, Path: "/cluster/v1/forward"})
			pr.Out.URL.Path = "/cluster/v1/forward" + r.URL.Path
			pr.Out.URL.RawQuery = r.URL.RawQuery
			pr.Out.Header.Del("Cookie")
			pr.Out.Header.Del("Authorization")
			pr.Out.Header.Set("X-Testudo-Identity", identity)
			pr.Out.Header.Set("X-Testudo-Via", m.cfg.ID)
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			http.Error(w, "the leader cannot be reached: "+err.Error(), http.StatusBadGateway)
		},
	}
	proxy.ServeHTTP(w, r)
}

// ---- the member API -----------------------------------------------------

// peer returns the member a request comes from, when it presented a valid
// member certificate.
func (m *Manager) peer(r *http.Request) (string, bool) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return "", false
	}
	leaf, err := m.verifyPeer([][]byte{r.TLS.PeerCertificates[0].Raw}, x509.ExtKeyUsageClientAuth)
	if err != nil {
		return "", false
	}
	return leaf.Subject.CommonName, true
}

// leaderOnly answers for a member that does not lead by naming the one
// that does, and reports whether the handler should go on.
func (m *Manager) leaderOnly(w http.ResponseWriter) (*Node, bool) {
	node := m.Node()
	if node == nil {
		http.Error(w, "not a cluster member", http.StatusServiceUnavailable)
		return nil, false
	}
	if !node.IsLeader() {
		if api := m.LeaderAPI(); api != "" {
			w.Header().Set("X-Testudo-Leader", api)
		}
		http.Error(w, "this member does not lead", http.StatusMisdirectedRequest)
		return nil, false
	}
	return node, true
}

func (m *Manager) routes() http.Handler {
	mux := http.NewServeMux()
	member := func(h func(http.ResponseWriter, *http.Request, string)) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			id, ok := m.peer(r)
			if !ok {
				http.Error(w, "members only", http.StatusUnauthorized)
				return
			}
			h(w, r, id)
		}
	}
	mux.HandleFunc("POST /cluster/v1/join", m.handleJoin)
	mux.HandleFunc("POST /cluster/v1/propose", member(m.handlePropose))
	mux.HandleFunc("POST /cluster/v1/renew", member(m.handleRenew))
	mux.HandleFunc("/cluster/v1/forward/", member(func(w http.ResponseWriter, r *http.Request, _ string) {
		if _, ok := m.leaderOnly(w); !ok {
			return
		}
		if m.cfg.Forwarded == nil {
			http.Error(w, "this member does not serve the console API", http.StatusServiceUnavailable)
			return
		}
		identity := r.Header.Get("X-Testudo-Identity")
		r2 := r.Clone(r.Context())
		r2.URL.Path = strings.TrimPrefix(r.URL.Path, "/cluster/v1/forward")
		r2.Header.Del("X-Testudo-Identity")
		m.cfg.Forwarded(w, r2, identity)
	}))
	return mux
}

func readJSON(w http.ResponseWriter, r *http.Request, into any) bool {
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 8<<20))
	if err != nil || json.Unmarshal(data, into) != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return false
	}
	return true
}

func (m *Manager) handleJoin(w http.ResponseWriter, r *http.Request) {
	node, ok := m.leaderOnly(w)
	if !ok {
		return
	}
	var req joinRequest
	if !readJSON(w, r, &req) {
		return
	}
	hash := tokenHash(req.Token)
	tok, ok := node.State().Tokens[hash]
	if !ok || time.Now().After(tok.Expires) {
		http.Error(w, "the join token is unknown, used or expired", http.StatusForbidden)
		return
	}
	if req.ID == "" || req.Raft == "" || req.API == "" {
		http.Error(w, "the request names no member", http.StatusBadRequest)
		return
	}
	if servers, err := node.Servers(); err == nil {
		for _, s := range servers {
			if s.ID == req.ID {
				http.Error(w, "a member with this id exists; remove it first", http.StatusConflict)
				return
			}
		}
	}
	// The token is used up before anything is handed out.
	c, _ := command(CmdToken, "", Token{Hash: hash, Remove: true})
	if err := node.Propose(r.Context(), c); err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	chain, serial, err := (pki.CA{Secrets: m.local, Name: caName}).SignRequest(req.CSR, req.ID, CertValidity)
	if err != nil {
		http.Error(w, "the certificate request was refused", http.StatusBadRequest)
		return
	}
	key := m.key()
	if key == nil {
		http.Error(w, "this member has no cluster key", http.StatusInternalServerError)
		return
	}
	if err := node.Add(req.ID, req.Raft); err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	// The member is announced on its behalf: it cannot propose before it
	// has caught up, and it is promoted only once it is announced.
	mc, _ := command(CmdMember, "", Member{ID: req.ID, Name: req.Name, Build: req.Build, Raft: req.Raft, API: req.API,
		Serial: serial, Voter: tok.Voter})
	if err := node.Propose(r.Context(), mc); err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(joinResponse{Chain: chain, Key: key})
}

func (m *Manager) handlePropose(w http.ResponseWriter, r *http.Request, from string) {
	node, ok := m.leaderOnly(w)
	if !ok {
		return
	}
	var c Command
	if !readJSON(w, r, &c) {
		return
	}
	// A member may report and announce for itself, replicate secrets and
	// issue tokens. Records, rollouts and revocations are the leader's.
	switch c.Type {
	case CmdResult:
		var res Result
		if json.Unmarshal(c.Payload, &res) != nil || res.Node != from {
			http.Error(w, "a member reports for itself", http.StatusForbidden)
			return
		}
	case CmdMember:
		var mem Member
		if json.Unmarshal(c.Payload, &mem) != nil || mem.ID != from || mem.Raft == "" {
			http.Error(w, "a member announces itself", http.StatusForbidden)
			return
		}
		// What only the cluster decides stays as it is.
		old := node.State().Members[from]
		mem.Serial, mem.Voter = old.Serial, old.Voter
		c.Payload, _ = json.Marshal(mem)
	case CmdSecret, CmdToken:
	default:
		http.Error(w, "members do not propose "+c.Type, http.StatusForbidden)
		return
	}
	if err := node.Propose(r.Context(), c); err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type renewal struct {
	CSR   []byte `json:"csr,omitempty"`
	Chain []byte `json:"chain,omitempty"`
}

func (m *Manager) handleRenew(w http.ResponseWriter, r *http.Request, from string) {
	node, ok := m.leaderOnly(w)
	if !ok {
		return
	}
	var req renewal
	if !readJSON(w, r, &req) {
		return
	}
	chain, serial, err := (pki.CA{Secrets: m.local, Name: caName}).SignRequest(req.CSR, from, CertValidity)
	if err != nil {
		http.Error(w, "the certificate request was refused", http.StatusBadRequest)
		return
	}
	mem := node.State().Members[from]
	mem.Serial = serial
	if c, err := command(CmdMember, "", mem); err == nil && mem.ID != "" {
		_ = node.Propose(r.Context(), c)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(renewal{Chain: chain})
}

// ---- housekeeping -------------------------------------------------------

// Renew replaces this member's certificate with a fresh one for a new key.
func (m *Manager) Renew(ctx context.Context) error {
	keyPEM, csr, err := pki.NewRequest(m.cfg.ID, []string{hostOf(m.cfg.RaftAdvertise), hostOf(m.cfg.APIAdvertise)})
	if err != nil {
		return err
	}
	var res renewal
	node := m.Node()
	if node != nil && node.IsLeader() {
		chain, serial, err := (pki.CA{Secrets: m.local, Name: caName}).SignRequest(csr, m.cfg.ID, CertValidity)
		if err != nil {
			return err
		}
		res.Chain = chain
		mem := node.State().Members[m.cfg.ID]
		mem.Serial = serial
		if c, err := command(CmdMember, "", mem); err == nil && mem.ID != "" {
			_ = node.Propose(ctx, c)
		}
	} else if err := m.send(ctx, "/cluster/v1/renew", renewal{CSR: csr}, &res); err != nil {
		return err
	}
	if _, err := tls.X509KeyPair(res.Chain, keyPEM); err != nil {
		return fmt.Errorf("cluster: the renewed certificate does not fit its key: %w", err)
	}
	// The certificate first: with the old key it is useless but harmless,
	// while a new key with the old certificate would break every
	// connection. Both are read together at the next handshake.
	if err := m.local.Put(entryNodeKey+".new", keyPEM); err != nil {
		return err
	}
	if err := m.local.Put(entryNodeCert, res.Chain); err != nil {
		return err
	}
	if err := m.local.Put(entryNodeKey, keyPEM); err != nil {
		return err
	}
	return m.local.Delete(entryNodeKey + ".new")
}

// certExpiry returns when this member's certificate expires.
func (m *Manager) certExpiry() (time.Time, error) {
	c, err := m.certificate()
	if err != nil {
		return time.Time{}, err
	}
	leaf, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		return time.Time{}, err
	}
	return leaf.NotAfter, nil
}

// housekeeping announces the member, promotes members that joined to be
// voters, and renews the certificate in time.
func (m *Manager) housekeeping(stop chan struct{}) {
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	announced := false
	for {
		select {
		case <-stop:
			return
		case <-tick.C:
		}
		node := m.Node()
		if node == nil {
			return
		}
		st := node.State()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		// Tell the cluster what this build can do. After an upgrade this
		// is what lets the leader use newer commands.
		me, known := st.Members[m.cfg.ID]
		meshKey := ""
		if m.cfg.MeshKey != nil {
			meshKey = m.cfg.MeshKey()
		}
		if known && (!announced || me.Build != m.cfg.Build || me.API != m.cfg.APIAdvertise || me.Raft != m.cfg.RaftAdvertise ||
			me.MeshKey != meshKey || fmt.Sprint(me.Commands) != fmt.Sprint(Supported)) {
			me.Name, me.Build, me.API, me.Raft, me.MeshKey = m.cfg.Name, m.cfg.Build, m.cfg.APIAdvertise, m.cfg.RaftAdvertise, meshKey
			me.Schema, me.Commands = schemaVersion(), Supported
			if c, err := command(CmdMember, "", me); err == nil && m.propose(ctx, c) == nil {
				announced = true
			}
		}
		if node.IsLeader() {
			if servers, err := node.Servers(); err == nil {
				for _, s := range servers {
					if mem, ok := st.Members[s.ID]; ok && mem.Voter && !s.Voter && mem.Commands != nil {
						_ = node.Promote(s.ID)
					}
				}
			}
		}
		if exp, err := m.certExpiry(); err == nil && time.Until(exp) < CertValidity/3 {
			_ = m.Renew(ctx)
		}
		cancel()
	}
}

// Remove takes a member out of the cluster. Its certificate stops being
// accepted by every member.
func (m *Manager) Remove(id string) error {
	node := m.Node()
	if node == nil {
		return errors.New("cluster: this node does not belong to a cluster")
	}
	if !node.IsLeader() {
		return ErrNotLeader
	}
	return node.Remove(id)
}

// Status is the cluster as one member sees it, for people and monitoring.
type Status struct {
	Member bool   `json:"member"`
	ID     string `json:"id"`
	Leader string `json:"leader,omitempty"`
	// Quorum is false when this member knows no leader: it serves what it
	// has and accepts no changes.
	Quorum  bool           `json:"quorum"`
	Stats   *Stats         `json:"stats,omitempty"`
	Members []MemberStatus `json:"members,omitempty"`
	Pending *Pending       `json:"pending,omitempty"`
	Rollout *Rollout       `json:"rollout,omitempty"`
	// ModelIndex is the newest record this member has.
	ModelIndex int64     `json:"model_index"`
	CertExpiry time.Time `json:"cert_expiry,omitempty"`
}

// MemberStatus is one member with what it last reported.
type MemberStatus struct {
	Member
	// Role is leader, voter or non-voter; InGroup is false for a member
	// that is announced and not (yet, or any more) part of the group.
	Role    string  `json:"role"`
	InGroup bool    `json:"in_group"`
	Result  *Result `json:"result,omitempty"`
	// State sums the report up: applied, pending (not there yet), failed,
	// drift, or unknown (no report).
	State string `json:"state"`
}

// Status describes the cluster from here.
func (m *Manager) Status() Status {
	node := m.Node()
	if node == nil {
		return Status{ID: m.cfg.ID, ModelIndex: m.cfg.Store.Current().Index()}
	}
	st := node.State()
	stats := node.Stats()
	leader, _ := node.Leader()
	out := Status{Member: true, ID: m.cfg.ID, Leader: leader, Quorum: leader != "", Stats: &stats, Pending: st.Pending,
		Rollout: st.Rollout, ModelIndex: stats.ModelIndex}
	out.CertExpiry, _ = m.certExpiry()
	servers, _ := node.Servers()
	seen := map[string]bool{}
	add := func(id string, voter, inGroup bool) {
		ms := MemberStatus{Member: st.Members[id], InGroup: inGroup, Role: "non-voter", State: "unknown"}
		ms.ID = id
		switch {
		case id == leader:
			ms.Role = "leader"
		case voter:
			ms.Role = "voter"
		}
		if r, ok := st.Results[id]; ok {
			ms.Result = &r
			switch {
			case !r.OK:
				ms.State = "failed"
			case r.Drift != "":
				ms.State = "drift"
			case r.Index < stats.ModelIndex:
				ms.State = "pending"
			default:
				ms.State = "applied"
			}
		}
		out.Members = append(out.Members, ms)
		seen[id] = true
	}
	for _, s := range servers {
		add(s.ID, s.Voter, true)
	}
	for id := range st.Members {
		if !seen[id] {
			add(id, false, false)
		}
	}
	return out
}

// Promote, Demote and TransferLeadership are the leader's; see Node.
func (m *Manager) Promote(id string) error {
	if n := m.Node(); n != nil {
		return n.Promote(id)
	}
	return errors.New("cluster: this node does not belong to a cluster")
}

func (m *Manager) Demote(id string) error {
	if n := m.Node(); n != nil {
		return n.Demote(id)
	}
	return errors.New("cluster: this node does not belong to a cluster")
}

func (m *Manager) TransferLeadership() error {
	if n := m.Node(); n != nil {
		return n.TransferLeadership()
	}
	return errors.New("cluster: this node does not belong to a cluster")
}

// RecoverAlone makes this member a cluster of one from what it has on
// disk. See Recover. The member must not be running.
func (m *Manager) RecoverAlone() error {
	if !m.Member() {
		return errors.New("cluster: this node does not belong to a cluster")
	}
	if m.Node() != nil {
		return errors.New("cluster: stop the member first")
	}
	return Recover(Options{ID: m.cfg.ID, Dir: filepath.Join(m.cfg.Dir, "raft"), Bind: m.cfg.RaftBind, Advertise: m.cfg.RaftAdvertise,
		Store: m.cfg.Store, Secrets: m.cfg.Secrets, Key: m.key})
}
