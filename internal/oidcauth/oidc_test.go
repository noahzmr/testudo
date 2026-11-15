package oidcauth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// idp is a small identity provider whose behaviour a test can bend.
type idp struct {
	t   *testing.T
	srv *httptest.Server

	mu       sync.Mutex
	keys     []jose.JSONWebKey // published
	signer   jose.JSONWebKey   // used to sign
	alg      jose.SignatureAlgorithm
	codes    map[string]map[string]string // code -> authorization request
	claims   map[string]any               // merged over the defaults
	noRotate bool
	jwksHits int
	refresh  map[string]string // refresh token -> subject
}

func newKey(t *testing.T, kid string) jose.JSONWebKey {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return jose.JSONWebKey{Key: k, KeyID: kid, Algorithm: "RS256", Use: "sig"}
}

func newIDP(t *testing.T) *idp {
	p := &idp{t: t, alg: jose.RS256, codes: map[string]map[string]string{}, claims: map[string]any{}, refresh: map[string]string{}}
	p.signer = newKey(t, "k1")
	p.keys = []jose.JSONWebKey{p.signer.Public()}
	mux := http.NewServeMux()
	p.srv = httptest.NewServer(mux)
	t.Cleanup(p.srv.Close)
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"issuer": p.srv.URL, "authorization_endpoint": p.srv.URL + "/auth", "token_endpoint": p.srv.URL + "/token",
			"jwks_uri": p.srv.URL + "/keys", "end_session_endpoint": p.srv.URL + "/logout", "backchannel_logout_supported": true,
			"id_token_signing_alg_values_supported": []string{"RS256", "ES256"},
		})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		defer p.mu.Unlock()
		p.jwksHits++
		json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: p.keys})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		p.mu.Lock()
		defer p.mu.Unlock()
		var sub, nonce string
		switch r.Form.Get("grant_type") {
		case "authorization_code":
			req, ok := p.codes[r.Form.Get("code")]
			if !ok {
				http.Error(w, `{"error":"invalid_grant"}`, 400)
				return
			}
			delete(p.codes, r.Form.Get("code"))
			// PKCE: the verifier has to hash to the challenge of the request.
			sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
			if req["code_challenge_method"] != "S256" || base64.RawURLEncoding.EncodeToString(sum[:]) != req["code_challenge"] {
				http.Error(w, `{"error":"invalid_grant","error_description":"pkce"}`, 400)
				return
			}
			sub, nonce = "sub-alice", req["nonce"]
		case "refresh_token":
			s, ok := p.refresh[r.Form.Get("refresh_token")]
			if !ok {
				http.Error(w, `{"error":"invalid_grant"}`, 400)
				return
			}
			sub = s
		}
		p.refresh["rt-"+sub] = sub
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "token_type": "Bearer", "expires_in": 300,
			"refresh_token": "rt-" + sub, "id_token": p.signLocked(map[string]any{"sub": sub, "nonce": nonce})})
	})
	return p
}

// signLocked signs the default claims with over merged in; a nil value
// removes a claim.
func (p *idp) signLocked(over map[string]any) string {
	now := time.Now()
	claims := map[string]any{"iss": p.srv.URL, "aud": "testudo", "iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
		"preferred_username": "alice", "email": "alice@example.com", "groups": []string{"/network/operators", "staff"}, "sid": "sess-1"}
	for _, m := range []map[string]any{over, p.claims} {
		for k, v := range m {
			if v == nil {
				delete(claims, k)
			} else {
				claims[k] = v
			}
		}
	}
	var key any = p.signer
	if p.alg == jose.HS256 {
		key = []byte("a shared secret that is long enough")
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: p.alg, Key: key}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		p.t.Fatal(err)
	}
	payload, _ := json.Marshal(claims)
	obj, err := signer.Sign(payload)
	if err != nil {
		p.t.Fatal(err)
	}
	out, _ := obj.CompactSerialize()
	return out
}

func (p *idp) sign(over map[string]any) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.signLocked(over)
}

// authorize plays the browser and the login page: it takes the URL the
// client produced and returns the code the provider would redirect with.
func (p *idp) authorize(authURL string) (code, state string) {
	u, err := url.Parse(authURL)
	if err != nil {
		p.t.Fatal(err)
	}
	q := u.Query()
	req := map[string]string{}
	for k := range q {
		req[k] = q.Get(k)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	code = "code-" + q.Get("state")[:8]
	p.codes[code] = req
	return code, q.Get("state")
}

func (p *idp) client(t *testing.T, mod func(*Config)) *Client {
	cfg := Config{Issuer: p.srv.URL, ClientID: "testudo", ClientSecret: "s3cret", RedirectURL: "https://fw.example.com/auth/oidc/callback"}
	if mod != nil {
		mod(&cfg)
	}
	c, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

var ctx = context.Background()

func TestLoginWithPKCE(t *testing.T) {
	p := newIDP(t)
	c := p.client(t, nil)
	flow, authURL := c.Start()
	u, _ := url.Parse(authURL)
	q := u.Query()
	if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" || q.Get("nonce") != flow.Nonce ||
		q.Get("state") != flow.State || !strings.Contains(q.Get("scope"), "openid") || q.Get("response_type") != "code" {
		t.Fatalf("authorization request: %v", q)
	}
	if strings.Contains(authURL, flow.Verifier) {
		t.Fatal("the PKCE verifier is in the URL")
	}
	code, _ := p.authorize(authURL)
	id, tok, err := c.Finish(ctx, flow, code)
	if err != nil {
		t.Fatal(err)
	}
	if id.Subject != "sub-alice" || id.Username != "alice" || id.Email != "alice@example.com" || id.SessionID != "sess-1" ||
		strings.Join(id.Groups, ",") != "/network/operators,staff" {
		t.Errorf("identity: %+v", id)
	}
	if tok.IDToken == "" || tok.Refresh == "" || time.Until(tok.Expiry) > 6*time.Minute || time.Until(tok.Expiry) < time.Minute {
		t.Errorf("tokens: refresh %q, expiry in %s", tok.Refresh, time.Until(tok.Expiry))
	}
	// A code is good once.
	if _, _, err := c.Finish(ctx, flow, code); err == nil {
		t.Error("the same code was accepted twice")
	}
	// Another login's verifier does not redeem this login's code.
	flow2, url2 := c.Start()
	code2, _ := p.authorize(url2)
	stolen := flow2
	stolen.Verifier = flow.Verifier
	if _, _, err := c.Finish(ctx, stolen, code2); err == nil {
		t.Error("a code was redeemed with the wrong PKCE verifier")
	}
}

func TestIDTokenValidation(t *testing.T) {
	cases := map[string]struct {
		claims map[string]any
		alg    jose.SignatureAlgorithm
		want   string
	}{
		"another login's nonce":     {claims: map[string]any{"nonce": "not-ours"}, want: "nonce"},
		"no nonce":                  {claims: map[string]any{"nonce": nil}, want: "nonce"},
		"another client":            {claims: map[string]any{"aud": "someone-else"}, want: "audience"},
		"another issuer":            {claims: map[string]any{"iss": "https://evil.example.com"}, want: "different provider"},
		"expired":                   {claims: map[string]any{"exp": time.Now().Add(-time.Minute).Unix()}, want: "expired"},
		"no subject":                {claims: map[string]any{"sub": ""}, want: "subject"},
		"several audiences, azp":    {claims: map[string]any{"aud": []string{"testudo", "other"}, "azp": "other"}, want: "another client"},
		"symmetric signature":       {alg: jose.HS256, want: "ID token"},
		"algorithm not on the list": {alg: jose.RS384, want: "ID token"},
	}
	for name, c := range cases {
		p := newIDP(t)
		client := p.client(t, nil)
		p.claims = c.claims
		if c.alg != "" {
			p.alg = c.alg
		}
		flow, authURL := client.Start()
		code, _ := p.authorize(authURL)
		_, _, err := client.Finish(ctx, flow, code)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want it to mention %q", name, err, c.want)
		}
	}
	// The allow-list is a list: with RS384 on it, the same token passes.
	p := newIDP(t)
	client := p.client(t, func(c *Config) { c.SigningAlgs = []string{"RS384"} })
	p.alg = jose.RS384
	flow, authURL := client.Start()
	code, _ := p.authorize(authURL)
	if _, _, err := client.Finish(ctx, flow, code); err != nil {
		t.Errorf("RS384 with RS384 allowed: %v", err)
	}
	for _, bad := range []string{"none", "HS256"} {
		if _, err := New(ctx, Config{Issuer: p.srv.URL, ClientID: "x", RedirectURL: "https://x/cb", SigningAlgs: []string{bad}}); err == nil {
			t.Errorf("algorithm %s was accepted in the configuration", bad)
		}
	}
}

func TestKeyRotationAndForeignKeys(t *testing.T) {
	p := newIDP(t)
	c := p.client(t, nil)
	login := func() error {
		flow, authURL := c.Start()
		code, _ := p.authorize(authURL)
		_, _, err := c.Finish(ctx, flow, code)
		return err
	}
	if err := login(); err != nil {
		t.Fatal(err)
	}
	// The provider rotates: a new key signs, both are published.
	p.mu.Lock()
	p.signer = newKey(t, "k2")
	p.keys = append(p.keys, p.signer.Public())
	hits := p.jwksHits
	p.mu.Unlock()
	if err := login(); err != nil {
		t.Fatalf("after rotation: %v", err)
	}
	if p.jwksHits == hits {
		t.Error("the keys were not fetched again for an unknown key id")
	}
	// The old key is withdrawn.
	p.mu.Lock()
	p.keys = p.keys[1:]
	p.mu.Unlock()
	if err := login(); err != nil {
		t.Fatalf("after the old key was withdrawn: %v", err)
	}
	// A key the provider does not publish signs nothing we accept, even
	// with a key id we know.
	p.mu.Lock()
	p.signer = newKey(t, "k2")
	p.mu.Unlock()
	if err := login(); err == nil {
		t.Error("a token signed with an unpublished key was accepted")
	}
	// An elliptic-curve key works when the algorithm is allowed.
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p.mu.Lock()
	p.signer = jose.JSONWebKey{Key: ec, KeyID: "ec1", Algorithm: "ES256", Use: "sig"}
	p.keys = append(p.keys, p.signer.Public())
	p.alg = jose.ES256
	p.mu.Unlock()
	if err := login(); err != nil {
		t.Errorf("ES256: %v", err)
	}
}

func TestRefresh(t *testing.T) {
	p := newIDP(t)
	c := p.client(t, nil)
	flow, authURL := c.Start()
	code, _ := p.authorize(authURL)
	id, tok, err := c.Finish(ctx, flow, code)
	if err != nil {
		t.Fatal(err)
	}
	// Groups changed at the provider; the refresh brings them.
	p.claims = map[string]any{"groups": []string{"staff"}}
	id2, tok2, err := c.Refresh(ctx, tok, id.Subject)
	if err != nil || strings.Join(id2.Groups, ",") != "staff" || tok2.IDToken == tok.IDToken || tok2.Refresh == "" {
		t.Fatalf("refresh: %+v %v", id2, err)
	}
	if _, _, err := c.Refresh(ctx, tok2, "sub-someone-else"); !errors.Is(err, ErrNoRefresh) {
		t.Errorf("refresh that returns another subject: %v", err)
	}
	if _, _, err := c.Refresh(ctx, Tokens{Refresh: "revoked"}, id.Subject); !errors.Is(err, ErrNoRefresh) {
		t.Errorf("refresh with a revoked token: %v", err)
	}
	if _, _, err := c.Refresh(ctx, Tokens{}, id.Subject); !errors.Is(err, ErrNoRefresh) {
		t.Errorf("refresh without a token: %v", err)
	}
}

func TestLogout(t *testing.T) {
	p := newIDP(t)
	c := p.client(t, nil)
	u, ok := c.LogoutURL("the-id-token", "https://fw.example.com/login")
	parsed, _ := url.Parse(u)
	if !ok || !strings.HasPrefix(u, p.srv.URL+"/logout?") || parsed.Query().Get("id_token_hint") != "the-id-token" ||
		parsed.Query().Get("post_logout_redirect_uri") != "https://fw.example.com/login" {
		t.Errorf("logout URL: %s", u)
	}
	event := map[string]any{backchannelEvent: map[string]any{}}
	good := func(over map[string]any) string {
		claims := map[string]any{"events": event, "jti": "j1", "nonce": nil, "preferred_username": nil, "groups": nil}
		for k, v := range over {
			claims[k] = v
		}
		return p.sign(claims)
	}
	sub, sid, err := c.VerifyLogoutToken(ctx, good(map[string]any{"sub": "sub-alice"}))
	if err != nil || sub != "sub-alice" || sid != "sess-1" {
		t.Fatalf("logout token: %q %q %v", sub, sid, err)
	}
	for name, tok := range map[string]string{
		"used twice":         good(map[string]any{"sub": "sub-alice"}),
		"with a nonce":       good(map[string]any{"sub": "sub-alice", "jti": "j2", "nonce": "n"}),
		"an ID token":        p.sign(map[string]any{"sub": "sub-alice", "jti": "j3"}),
		"no id":              good(map[string]any{"sub": "sub-alice", "jti": nil}),
		"nobody named":       good(map[string]any{"sub": "", "sid": nil, "jti": "j4"}),
		"for another client": good(map[string]any{"sub": "sub-alice", "jti": "j5", "aud": "other"}),
	} {
		if _, _, err := c.VerifyLogoutToken(ctx, tok); err == nil {
			t.Errorf("logout token %s was accepted", name)
		}
	}
}
