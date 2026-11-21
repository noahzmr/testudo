package confapi

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/noahzmr/testudo/internal/confstore"
	"github.com/noahzmr/testudo/internal/model"
	"github.com/noahzmr/testudo/internal/perm"
)

// SecretKeeper puts a value into the node's secret store under a new name
// that starts with prefix, and returns that name.
type SecretKeeper interface {
	StoreSecret(prefix string, value []byte) (ref string, err error)
}

// AuditReader returns the newest rows of the audit log.
type AuditReader func(ctx context.Context, limit int) ([]AuditRow, error)

// TokenPrefix starts every API token, so that one found in a log or a
// repository can be recognised for what it is.
const TokenPrefix = "tdo_"

// HashToken is how a token is stored and looked up.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// oidcClientSecret stores the identity provider's client secret on the node
// and returns the name of its entry for the provider object.
func (s *Server) oidcClientSecret(w http.ResponseWriter, r *http.Request) {
	if s.Secrets == nil {
		fail(w, http.StatusServiceUnavailable, "unavailable", "secrets cannot be stored on this node")
		return
	}
	if !who(r).Can(SystemArea, "write") {
		fail(w, http.StatusForbidden, "forbidden", "needs system:write")
		return
	}
	var in struct {
		Secret string `json:"secret"`
	}
	body, err := readBody(w, r, 1<<14)
	if err != nil || json.Unmarshal(body, &in) != nil || strings.TrimSpace(in.Secret) == "" {
		fail(w, http.StatusBadRequest, "bad_request", "give the secret")
		return
	}
	ref, err := s.Secrets.StoreSecret("oidc", []byte(strings.TrimSpace(in.Secret)+"\n"))
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal", "could not store the secret")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"client_secret_ref": ref})
}

// createToken makes an API token for the caller. The token is shown this
// one time; the model keeps its hash. It can carry any of the caller's own
// permissions and nothing beyond them.
func (s *Server) createToken(w http.ResponseWriter, r *http.Request) {
	id := who(r)
	if id.Token {
		fail(w, http.StatusForbidden, "forbidden", "a token cannot create tokens; log in")
		return
	}
	var in struct {
		Name        string   `json:"name"`
		Permissions []string `json:"permissions"`
		TTLHours    int      `json:"ttl_hours"`
	}
	body, err := readBody(w, r, 1<<14)
	if err != nil || json.Unmarshal(body, &in) != nil || in.Name == "" || len(in.Permissions) == 0 {
		fail(w, http.StatusBadRequest, "bad_request", "give a name and at least one permission")
		return
	}
	if in.TTLHours < 0 || in.TTLHours > 24*366 {
		fail(w, http.StatusBadRequest, "bad_request", "ttl_hours must be between 0 (no expiry) and one year")
		return
	}
	for _, p := range in.Permissions {
		if !perm.Within(id.Permissions, p, SiteOf(s.Store.Current())) {
			fail(w, http.StatusForbidden, "forbidden", "you do not hold "+p+" yourself")
			return
		}
	}
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		fail(w, http.StatusInternalServerError, "internal", "could not create the token")
		return
	}
	token := TokenPrefix + base64.RawURLEncoding.EncodeToString(raw[:])
	obj := &model.APIToken{Meta: model.Meta{ID: confstore.NewID(), Name: in.Name}, Owner: id.Name,
		Permissions: in.Permissions, Hash: HashToken(token)}
	if in.TTLHours > 0 {
		exp := time.Now().Add(time.Duration(in.TTLHours) * time.Hour).UTC()
		obj.ExpiresAt = &exp
	}
	js, _ := json.Marshal(obj)
	// A token changes nothing in the running system, so it is confirmed
	// right away instead of waiting for someone to press a button.
	if _, err := s.Engine.Apply(r.Context(), id.Name, "API token "+in.Name, []confstore.Op{{Type: confstore.OpCreate, Kind: model.KindAPIToken, ID: obj.ID, Object: js}}); err != nil {
		s.writeErr(w, err)
		return
	}
	if err := s.Engine.Confirm(id.Name); err != nil {
		s.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"id": obj.ID, "name": in.Name, "token": token,
		"permissions": in.Permissions, "expires_at": obj.ExpiresAt})
}

// FindToken returns the token object a presented token belongs to, when it
// is valid now.
func FindToken(st *confstore.State, token string, now time.Time) (*model.APIToken, bool) {
	if st == nil || !strings.HasPrefix(token, TokenPrefix) {
		return nil, false
	}
	hash := HashToken(token)
	for _, e := range st.List(model.KindAPIToken) {
		t := e.(*model.APIToken)
		if t.Hash != hash {
			continue
		}
		if t.Disabled || (t.ExpiresAt != nil && now.After(*t.ExpiresAt)) {
			return nil, false
		}
		return t, true
	}
	return nil, false
}

// AuditRow is one entry of the audit log: who did what, from which process,
// and how it ended.
type AuditRow struct {
	Time    time.Time `json:"time"`
	Actor   string    `json:"actor"`
	Op      string    `json:"op"`
	Detail  string    `json:"detail"`
	Result  string    `json:"result"`
	PeerUID uint32    `json:"peer_uid"`
}

// audit lists the newest audit rows: logins and logouts with their source,
// configuration changes with what changed, applies, confirmations,
// rollbacks, and every privileged operation on the kernel.
func (s *Server) audit(w http.ResponseWriter, r *http.Request) {
	if s.Audit == nil {
		fail(w, http.StatusServiceUnavailable, "unavailable", "the audit log is not available")
		return
	}
	if !who(r).Can(SystemArea, "read") {
		fail(w, http.StatusForbidden, "forbidden", "needs system:read")
		return
	}
	limit := 200
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 5000 {
			fail(w, http.StatusBadRequest, "bad_request", "limit must be between 1 and 5000")
			return
		}
		limit = n
	}
	rows, err := s.Audit(r.Context(), limit)
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal", "could not read the audit log")
		return
	}
	if op := r.URL.Query().Get("op"); op != "" {
		kept := rows[:0]
		for _, row := range rows {
			if strings.HasPrefix(row.Op, op) {
				kept = append(kept, row)
			}
		}
		rows = kept
	}
	if rows == nil {
		rows = []AuditRow{}
	}
	writeJSON(w, http.StatusOK, rows)
}
