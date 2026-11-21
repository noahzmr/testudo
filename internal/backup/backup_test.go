package backup

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/noahzmr/testudo/internal/confstore"
	"github.com/noahzmr/testudo/internal/model"
	"github.com/noahzmr/testudo/internal/secrets"
)

var pass = []byte("correct horse battery")

// node builds a storage directory with a model, a secret, users and a
// file that must stay out of the backup.
func node(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	store, err := confstore.Open(filepath.Join(dir, "config"))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"lan", "wan"} {
		if _, err := store.Create(context.Background(), "admin", &model.Zone{Meta: model.Meta{Name: name}, DefaultAction: "drop"}); err != nil {
			t.Fatal(err)
		}
	}
	store.Close()
	if err := (secrets.Store{Dir: filepath.Join(dir, "secrets")}).Put("wg-key-1", []byte("private")); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{"users.json": `{"users":[]}`, "testudo.db": "metrics", "cluster/raft/raft.db": "consensus"} {
		p := filepath.Join(dir, name)
		os.MkdirAll(filepath.Dir(p), 0o700)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func create(t *testing.T, dir string) []byte {
	t.Helper()
	var b bytes.Buffer
	m, err := Create(&b, dir, pass)
	if err != nil {
		t.Fatal(err)
	}
	if m.ModelIndex != 2 {
		t.Errorf("manifest model index %d", m.ModelIndex)
	}
	got := strings.Join(m.Files, ",")
	if got != "config/config.log,secrets/wg-key-1,users.json" {
		t.Errorf("archived files: %s", got)
	}
	return b.Bytes()
}

func TestRoundTrip(t *testing.T) {
	archive := create(t, node(t))
	if bytes.Contains(archive, []byte("private")) || bytes.Contains(archive, []byte("lan")) {
		t.Fatal("the archive is not encrypted")
	}
	target := t.TempDir()
	m, err := Restore(bytes.NewReader(archive), target, pass, false)
	if err != nil {
		t.Fatal(err)
	}
	if m.ModelIndex != 2 {
		t.Errorf("restored manifest %+v", m)
	}
	st, err := confstore.ReadState(filepath.Join(target, "config"))
	if err != nil || len(st.List(model.KindZone)) != 2 {
		t.Fatalf("restored model: %v", err)
	}
	if v, err := (secrets.Store{Dir: filepath.Join(target, "secrets")}).Get("wg-key-1"); err != nil || string(v) != "private" {
		t.Errorf("restored secret: %q %v", v, err)
	}
	if fi, err := os.Stat(filepath.Join(target, "secrets", "wg-key-1")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("secret file mode: %v %v", fi, err)
	}
	for _, left := range []string{"testudo.db", "cluster/raft/raft.db"} {
		if _, err := os.Stat(filepath.Join(target, left)); err == nil {
			t.Errorf("%s was restored", left)
		}
	}
	// A second restore over the configuration needs force.
	if _, err := Restore(bytes.NewReader(archive), target, pass, false); err == nil || !strings.Contains(err.Error(), "--force") {
		t.Errorf("restore over a configuration: %v", err)
	}
	if _, err := Restore(bytes.NewReader(archive), target, pass, true); err != nil {
		t.Errorf("forced restore: %v", err)
	}
}

func TestWrongPassphraseAndTampering(t *testing.T) {
	archive := create(t, node(t))
	for name, tc := range map[string]struct {
		data []byte
		pass []byte
	}{
		"wrong passphrase": {archive, []byte("incorrect horse battery")},
		"changed body":     {flip(archive, len(archive)-5), pass},
		"changed header":   {[]byte(strings.Replace(string(archive), `"p":1`, `"p":2`, 1)), pass},
		"truncated":        {archive[:len(archive)-20], pass},
	} {
		target := t.TempDir()
		if _, err := Restore(bytes.NewReader(tc.data), target, tc.pass, false); err == nil {
			t.Errorf("%s: restored", name)
		}
		if entries, _ := os.ReadDir(target); len(entries) != 0 {
			t.Errorf("%s: wrote %d entries before failing", name, len(entries))
		}
	}
	if _, err := Create(&bytes.Buffer{}, node(t), []byte("short")); err == nil {
		t.Error("a short passphrase was accepted")
	}
	if _, _, err := Open(strings.NewReader("not a backup"), pass); err == nil {
		t.Error("garbage opened")
	}
}

func flip(b []byte, i int) []byte {
	c := append([]byte(nil), b...)
	c[i] ^= 0x01
	return c
}

// TestHostileEntriesAreRefused: even a correctly sealed archive cannot
// write outside the storage directory or files that are no backup's.
func TestHostileEntriesAreRefused(t *testing.T) {
	for _, name := range []string{"../escape", "/etc/passwd", "cluster/member.json", "secrets/../../x"} {
		var plain bytes.Buffer
		gz := gzip.NewWriter(&plain)
		tw := tar.NewWriter(gz)
		for _, e := range []struct{ n, b string }{{manifestName, "{}"}, {name, "x"}} {
			tw.WriteHeader(&tar.Header{Name: e.n, Mode: 0o600, Size: int64(len(e.b)), Typeflag: tar.TypeReg})
			tw.Write([]byte(e.b))
		}
		tw.Close()
		gz.Close()
		var archive bytes.Buffer
		if err := seal(&archive, plain.Bytes(), pass); err != nil {
			t.Fatal(err)
		}
		target := t.TempDir()
		if _, err := Restore(&archive, target, pass, true); err == nil || !strings.Contains(err.Error(), "unexpected entry") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestRestoreWaitsForTheDaemon(t *testing.T) {
	archive := create(t, node(t))
	target := t.TempDir()
	store, err := confstore.Open(filepath.Join(target, "config"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := Restore(bytes.NewReader(archive), target, pass, true); err == nil || !strings.Contains(err.Error(), "stop testudo") {
		t.Errorf("restore while the store is open: %v", err)
	}
}
