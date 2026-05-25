// Package auth stores user credentials in a JSON file at
// ~/.testudo/users.json and verifies passwords via bcrypt. Used by the
// Web UI to gate access.
//
// On first run, the store auto-creates a default user "testudo" with a
// random password printed once to stderr (CLI: `testudo user passwd` rotates).
package auth

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// User is a single credential record.
type User struct {
	Name      string    `json:"name"`
	Hash      string    `json:"hash"` // bcrypt
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Store is the live user table backed by a JSON file. Concurrent use is
// safe - the lock guards both in-memory and on-disk state.
type Store struct {
	mu    sync.RWMutex
	path  string
	users map[string]User
}

// Open loads the user file, or creates an empty store on a missing file.
// Use Bootstrap to seed a default user.
func Open(path string) (*Store, error) {
	s := &Store{path: path, users: make(map[string]User)}
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
		s.users[u.Name] = u
	}
	return s, nil
}

// Bootstrap ensures a default user exists. Returns the freshly-generated
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
	now := time.Now()
	s.users[defaultName] = User{
		Name: defaultName, Hash: string(hash),
		CreatedAt: now, UpdatedAt: now,
	}
	if err := s.saveLocked(); err != nil {
		return "", err
	}
	return pw, nil
}

// SetPassword updates an existing user, or creates one if absent.
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
	now := time.Now()
	u, ok := s.users[name]
	if !ok {
		u = User{Name: name, CreatedAt: now}
	}
	u.Hash = string(hash)
	u.UpdatedAt = now
	s.users[name] = u
	return s.saveLocked()
}

// Verify returns true when (name, password) matches a stored credential.
func (s *Store) Verify(name, password string) bool {
	s.mu.RLock()
	u, ok := s.users[name]
	s.mu.RUnlock()
	if !ok {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(u.Hash), []byte(password)) == nil
}

// ListNames returns the user names in arbitrary order. Useful for ops UIs.
func (s *Store) ListNames() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.users))
	for name := range s.users {
		out = append(out, name)
	}
	return out
}

// saveLocked writes users.json atomically. Caller holds s.mu (write lock).
func (s *Store) saveLocked() error {
	out := make([]User, 0, len(s.users))
	for _, u := range s.users {
		out = append(out, u)
	}
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
