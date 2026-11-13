// Package auth stores Web UI users in a JSON file at ~/.testudo/users.json:
// bcrypt password hashes, a role, and an optional TOTP secret. It is the
// identity layer every audit row and every PAM grant hangs off.
//
// On first run, the store auto-creates a default admin "testudo" with a
// random password printed once to stderr (CLI: `testudo user passwd` rotates).
//
// Secrets rule: TOTP secrets live only in the 0600 users file. They are shown
// once at enrollment (as an otpauth:// URI) and never logged.
package auth

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// Role is what a user may do. Ranks are ordered: a higher role can do
// everything a lower one can, except that approving PAM grants is reserved
// to approver and admin (separation of duties: an operator cannot approve).
type Role string

const (
	RoleViewer   Role = "viewer"   // read-only
	RoleApprover Role = "approver" // read-only + approve/deny access requests
	RoleOperator Role = "operator" // mutate network state, request access
	RoleAdmin    Role = "admin"    // everything: users, settings, policy import, enforce
)

// Valid reports whether r is a known role.
func (r Role) Valid() bool {
	switch r {
	case RoleViewer, RoleApprover, RoleOperator, RoleAdmin:
		return true
	}
	return false
}

// Rank orders roles for "at least X" checks.
func (r Role) Rank() int {
	switch r {
	case RoleAdmin:
		return 3
	case RoleOperator:
		return 2
	case RoleApprover:
		return 1
	default:
		return 0
	}
}

// AtLeast reports whether r grants everything min grants.
func (r Role) AtLeast(min Role) bool { return r.Rank() >= min.Rank() }

// CanApprove reports whether r may approve or deny access requests.
func (r Role) CanApprove() bool { return r == RoleApprover || r == RoleAdmin }

// User is a single credential record.
type User struct {
	Name       string    `json:"name"`
	Hash       string    `json:"hash"` // bcrypt
	Role       Role      `json:"role"`
	TOTPSecret string    `json:"totp_secret,omitempty"` // base32; "" = MFA not enrolled
	Disabled   bool      `json:"disabled,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// MFAEnrolled reports whether the user must present a TOTP code.
func (u User) MFAEnrolled() bool { return u.TOTPSecret != "" }

// Public returns the user without secret material, for listings and /api/me.
func (u User) Public() User {
	u.Hash = ""
	if u.TOTPSecret != "" {
		u.TOTPSecret = "enrolled"
	}
	return u
}

// Authentication errors. Callers show ErrInvalidCredentials for every failure
// except ErrTOTPRequired, which tells the login form to ask for a code.
var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrTOTPRequired       = errors.New("one-time code required")
	ErrDisabled           = errors.New("account disabled")
	ErrNotFound           = errors.New("no such user")
	ErrLastAdmin          = errors.New("cannot remove or demote the last admin")
)

// Store is the live user table backed by a JSON file. Concurrent use is
// safe - the lock guards both in-memory and on-disk state.
type Store struct {
	mu    sync.RWMutex
	path  string
	users map[string]User
	now   func() time.Time
}

// Open loads the user file, or creates an empty store on a missing file.
// Users written by older builds carry no role; they become admins, because
// the single bootstrap user has to keep working after an upgrade.
func Open(path string) (*Store, error) {
	s := &Store{path: path, users: make(map[string]User), now: time.Now}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return s, nil
		}
		return nil, fmt.Errorf("read users file: %w", err)
	}
	var raw []User
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse users file: %w", err)
	}
	for _, u := range raw {
		if !u.Role.Valid() {
			u.Role = RoleAdmin
		}
		s.users[u.Name] = u
	}
	return s, nil
}

// Bootstrap ensures a default admin exists. Returns the freshly-generated
// password if one was created; empty if a user was already present.
// Caller is responsible for printing/storing the returned password - it is
// not recoverable after this call returns.
func (s *Store) Bootstrap(defaultName string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.users) > 0 {
		return "", nil
	}
	pw := randomPassword(16)
	hash, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	now := s.now()
	s.users[defaultName] = User{
		Name: defaultName, Hash: string(hash), Role: RoleAdmin,
		CreatedAt: now, UpdatedAt: now,
	}
	if err := s.saveLocked(); err != nil {
		return "", err
	}
	return pw, nil
}

// Add creates a user with a password and role. Fails when the name exists.
func (s *Store) Add(name, password string, role Role) error {
	name = strings.TrimSpace(name)
	if err := validateName(name); err != nil {
		return err
	}
	if password == "" {
		return errors.New("password required")
	}
	if !role.Valid() {
		return fmt.Errorf("invalid role %q (viewer / approver / operator / admin)", role)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.users[name]; exists {
		return fmt.Errorf("user %q already exists", name)
	}
	now := s.now()
	s.users[name] = User{Name: name, Hash: string(hash), Role: role, CreatedAt: now, UpdatedAt: now}
	return s.saveLocked()
}

// SetPassword updates an existing user's password, or creates an admin if
// the name is unknown (the historical `user passwd` contract).
func (s *Store) SetPassword(name, password string) error {
	if name == "" || password == "" {
		return errors.New("name and password required")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	u, ok := s.users[name]
	if !ok {
		u = User{Name: name, Role: RoleAdmin, CreatedAt: now}
	}
	u.Hash = string(hash)
	u.UpdatedAt = now
	s.users[name] = u
	return s.saveLocked()
}

// SetRole changes a user's role. Refuses to demote the last admin.
func (s *Store) SetRole(name string, role Role) error {
	if !role.Valid() {
		return fmt.Errorf("invalid role %q (viewer / approver / operator / admin)", role)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[name]
	if !ok {
		return ErrNotFound
	}
	if u.Role == RoleAdmin && role != RoleAdmin && s.adminCountLocked() == 1 {
		return ErrLastAdmin
	}
	u.Role = role
	u.UpdatedAt = s.now()
	s.users[name] = u
	return s.saveLocked()
}

// SetDisabled blocks or unblocks logins without deleting the record (and its
// audit trail). Refuses to disable the last enabled admin.
func (s *Store) SetDisabled(name string, disabled bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[name]
	if !ok {
		return ErrNotFound
	}
	if disabled && u.Role == RoleAdmin && !u.Disabled && s.adminCountLocked() == 1 {
		return ErrLastAdmin
	}
	u.Disabled = disabled
	u.UpdatedAt = s.now()
	s.users[name] = u
	return s.saveLocked()
}

// Delete removes a user. Refuses to delete the last admin.
func (s *Store) Delete(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[name]
	if !ok {
		return ErrNotFound
	}
	if u.Role == RoleAdmin && s.adminCountLocked() == 1 {
		return ErrLastAdmin
	}
	delete(s.users, name)
	return s.saveLocked()
}

// adminCountLocked counts enabled admins. Caller holds s.mu.
func (s *Store) adminCountLocked() int {
	n := 0
	for _, u := range s.users {
		if u.Role == RoleAdmin && !u.Disabled {
			n++
		}
	}
	return n
}

// EnrollTOTP generates a fresh TOTP secret for the user and returns the
// otpauth:// URI to show exactly once (QR encoding happens client-side). An
// existing secret is replaced - re-enrolling is how a lost authenticator is
// recovered by an admin.
func (s *Store) EnrollTOTP(name, issuer string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[name]
	if !ok {
		return "", ErrNotFound
	}
	raw := make([]byte, 20)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)
	u.TOTPSecret = secret
	u.UpdatedAt = s.now()
	s.users[name] = u
	if err := s.saveLocked(); err != nil {
		return "", err
	}
	if issuer == "" {
		issuer = "Testudo"
	}
	return otpauthURI(issuer, name, secret), nil
}

// DisableTOTP removes the user's TOTP secret.
func (s *Store) DisableTOTP(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[name]
	if !ok {
		return ErrNotFound
	}
	u.TOTPSecret = ""
	u.UpdatedAt = s.now()
	s.users[name] = u
	return s.saveLocked()
}

// otpauthURI renders the standard provisioning URI authenticator apps scan.
func otpauthURI(issuer, account, secret string) string {
	label := url.PathEscape(issuer + ":" + account)
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", "6")
	q.Set("period", "30")
	return "otpauth://totp/" + label + "?" + q.Encode()
}

// Authenticate checks a password and, when the user is enrolled, a TOTP code.
// It returns ErrTOTPRequired when the password is right but no code was given
// so the login form can ask for one; every other failure is
// ErrInvalidCredentials (no user enumeration). Disabled accounts never log in.
func (s *Store) Authenticate(name, password, code string) (User, error) {
	s.mu.RLock()
	u, ok := s.users[name]
	s.mu.RUnlock()
	if !ok {
		// Burn comparable time so a missing user is not distinguishable.
		_ = bcrypt.CompareHashAndPassword([]byte(dummyHash), []byte(password))
		return User{}, ErrInvalidCredentials
	}
	if bcrypt.CompareHashAndPassword([]byte(u.Hash), []byte(password)) != nil {
		return User{}, ErrInvalidCredentials
	}
	if u.Disabled {
		return User{}, ErrDisabled
	}
	if u.MFAEnrolled() {
		code = strings.ReplaceAll(strings.TrimSpace(code), " ", "")
		if code == "" {
			return User{}, ErrTOTPRequired
		}
		if !ValidateTOTP(u.TOTPSecret, code, s.now()) {
			return User{}, ErrInvalidCredentials
		}
	}
	return u, nil
}

// Verify returns true when (name, password) matches a stored credential and
// the account is enabled. It ignores MFA - use Authenticate for logins.
func (s *Store) Verify(name, password string) bool {
	s.mu.RLock()
	u, ok := s.users[name]
	s.mu.RUnlock()
	if !ok || u.Disabled {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(u.Hash), []byte(password)) == nil
}

// Get returns a user record without secret material.
func (s *Store) Get(name string) (User, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[name]
	if !ok {
		return User{}, false
	}
	return u.Public(), true
}

// List returns every user (no secret material), sorted by name.
func (s *Store) List() []User {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]User, 0, len(s.users))
	for _, u := range s.users {
		out = append(out, u.Public())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// ListNames returns the user names in sorted order. Useful for ops UIs.
func (s *Store) ListNames() []string {
	us := s.List()
	out := make([]string, 0, len(us))
	for _, u := range us {
		out = append(out, u.Name)
	}
	return out
}

func validateName(name string) error {
	if name == "" {
		return errors.New("name required")
	}
	if len(name) > 64 {
		return errors.New("name is at most 64 characters")
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '_', r == '-', r == '@':
		default:
			return fmt.Errorf("name may contain letters, digits, '.', '_', '-' and '@' only")
		}
	}
	return nil
}

// saveLocked writes users.json atomically. Caller holds s.mu (write lock).
func (s *Store) saveLocked() error {
	out := make([]User, 0, len(s.users))
	for _, u := range s.users {
		out = append(out, u)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func randomPassword(bytes int) string {
	b := make([]byte, bytes)
	_, _ = rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)[:bytes]
}

// dummyHash is a valid bcrypt hash compared against when the user does not
// exist, so the response time does not reveal which names are real.
const dummyHash = "$2a$10$7EqJtq98hPqEX7fNZaFWoOhi5XSS5xUx8c1bFw7p8m0gv0qJg9v5W"
