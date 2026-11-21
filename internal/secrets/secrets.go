// Package secrets is the node-local store for key material: WireGuard
// private and preshared keys, later certificate keys. The configuration
// model only ever holds the name of an entry, so key material never enters
// the configuration log, the audit trail or a cluster's replicated state.
//
// An entry is one file with mode 0600 in a directory with mode 0700.
package secrets

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// ErrNotFound is returned for an entry that does not exist.
var ErrNotFound = errors.New("secrets: no such entry")

var nameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`)

// ValidName reports whether name can be an entry. Names are file names, so
// nothing that could leave the directory is accepted.
func ValidName(name string) bool { return nameRe.MatchString(name) && !strings.Contains(name, "..") }

// Store is a directory of secrets.
type Store struct {
	Dir string
	// Replicate, when set, takes over every write: on a cluster member a
	// secret has to reach the other members too, and it is the cluster
	// that then writes it into each member's directory (through a Store
	// without Replicate). remove is true for a deletion.
	Replicate func(name string, value []byte, remove bool) error
}

// Local returns the store without replication: what the cluster itself
// writes through.
func (s Store) Local() Store { return Store{Dir: s.Dir} }

func (s Store) path(name string) (string, error) {
	if !ValidName(name) {
		return "", fmt.Errorf("secrets: bad entry name %q", name)
	}
	return filepath.Join(s.Dir, name), nil
}

// Put writes an entry, replacing an existing one atomically.
func (s Store) Put(name string, value []byte) error {
	p, err := s.path(name)
	if err != nil {
		return err
	}
	if s.Replicate != nil {
		return s.Replicate(name, value, false)
	}
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, value, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// Get reads an entry.
func (s Store) Get(name string) ([]byte, error) {
	p, err := s.path(name)
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, name)
	}
	return b, err
}

// Has reports whether an entry exists.
func (s Store) Has(name string) bool {
	p, err := s.path(name)
	if err != nil {
		return false
	}
	_, err = os.Stat(p)
	return err == nil
}

// Delete removes an entry; a missing one is not an error.
func (s Store) Delete(name string) error {
	p, err := s.path(name)
	if err != nil {
		return err
	}
	if s.Replicate != nil {
		return s.Replicate(name, nil, true)
	}
	if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// List returns the names of the entries, sorted.
func (s Store) List() ([]string, error) {
	entries, err := os.ReadDir(s.Dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if e.Type().IsRegular() && ValidName(e.Name()) && !strings.HasSuffix(e.Name(), ".tmp") {
			out = append(out, e.Name())
		}
	}
	return out, nil
}
