package secrets

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestStore(t *testing.T) {
	s := Store{Dir: filepath.Join(t.TempDir(), "keys")}
	if err := s.Put("wg0-key", []byte("secret")); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(filepath.Join(s.Dir, "wg0-key")); fi.Mode().Perm() != 0o600 {
		t.Errorf("entry mode %v", fi.Mode().Perm())
	}
	if fi, _ := os.Stat(s.Dir); fi.Mode().Perm() != 0o700 {
		t.Errorf("directory mode %v", fi.Mode().Perm())
	}
	if got, err := s.Get("wg0-key"); err != nil || string(got) != "secret" || !s.Has("wg0-key") {
		t.Errorf("get: %q %v", got, err)
	}
	if _, err := s.Get("absent"); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing entry: %v", err)
	}
	for _, bad := range []string{"", "../etc/passwd", "a/b", ".hidden", "a..b", "x y"} {
		if err := s.Put(bad, []byte("x")); err == nil {
			t.Errorf("name %q accepted", bad)
		}
		if s.Has(bad) {
			t.Errorf("Has(%q)", bad)
		}
	}
	if err := s.Delete("wg0-key"); err != nil || s.Has("wg0-key") || s.Delete("wg0-key") != nil {
		t.Errorf("delete: %v", err)
	}
}
