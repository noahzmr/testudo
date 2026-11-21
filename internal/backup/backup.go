// Package backup writes and restores an encrypted copy of what a node needs
// to come back after it is lost: the configuration model with its history,
// the secrets the model refers to (tunnel keys, certificate keys, the
// cluster's key and authority), the console's users, settings, the SSH
// user CA, TLS material and the ACME account.
//
// What is left out on purpose: the SQLite database (metrics, flows,
// sessions: large and replaceable), packet captures, the consensus state
// in cluster/ (a restored member joins its cluster again) and everything
// rendered from the model, which the next start renders again.
//
// The archive is a tar stream, gzip-compressed and sealed with AES-256-GCM
// under a key derived from a passphrase with scrypt. The header, which
// carries the KDF parameters, is authenticated as additional data, so a
// changed header fails like a changed body. Nothing is written on restore
// before the whole archive has been decrypted and checked.
package backup

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/crypto/scrypt"

	"github.com/noahzmr/testudo/internal/confstore"
)

// Magic opens every archive.
const Magic = "TESTUDO-BACKUP-1\n"

// MinPassphrase is the shortest passphrase accepted for a new archive.
const MinPassphrase = 12

// Limits against a hostile or broken archive.
const (
	maxHeader = 4 << 10
	maxBody   = 1 << 30
	maxFile   = 256 << 20
)

// Files and directories under the storage directory that go into a backup.
var (
	files = []string{"config/config.log", "config/config.snapshot", "users.json", "settings.json", "firewall.json", "proxy/acme.json"}
	dirs  = []string{"secrets", "sshca", "tls"}
)

// allowed reports whether a path in an archive belongs to a backup; restore
// writes nothing else.
func allowed(name string) bool {
	for _, f := range files {
		if name == f {
			return true
		}
	}
	for _, d := range dirs {
		if strings.HasPrefix(name, d+"/") {
			return true
		}
	}
	return false
}

// header is the archive's first line after Magic.
type header struct {
	KDF   string `json:"kdf"`
	N     int    `json:"n"`
	R     int    `json:"r"`
	P     int    `json:"p"`
	Salt  []byte `json:"salt"`
	Nonce []byte `json:"nonce"`
}

// Manifest describes an archive's content.
type Manifest struct {
	Created    time.Time `json:"created"`
	ModelIndex int64     `json:"model_index"`
	Files      []string  `json:"files"`
}

const manifestName = "MANIFEST.json"

// scrypt cost: 2^15 needs 32 MiB and takes a fraction of a second.
var kdfN = 1 << 15

func deriveKey(pass []byte, h header) ([]byte, error) {
	if h.KDF != "scrypt" || h.N < 1<<14 || h.N > 1<<20 || h.R != 8 || h.P < 1 || h.P > 4 || len(h.Salt) != 16 {
		return nil, errors.New("backup: unsupported key derivation parameters")
	}
	return scrypt.Key(pass, h.Salt, h.N, h.R, h.P, 32)
}

// Create writes an archive of storageDir to w.
func Create(w io.Writer, storageDir string, pass []byte) (Manifest, error) {
	if len(pass) < MinPassphrase {
		return Manifest{}, fmt.Errorf("backup: the passphrase needs at least %d characters", MinPassphrase)
	}
	content := map[string][]byte{}
	for _, f := range files {
		b, err := os.ReadFile(filepath.Join(storageDir, filepath.FromSlash(f)))
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return Manifest{}, err
		}
		content[f] = b
	}
	for _, d := range dirs {
		root := filepath.Join(storageDir, d)
		err := filepath.WalkDir(root, func(p string, e fs.DirEntry, err error) error {
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) && p == root {
					return filepath.SkipDir
				}
				return err
			}
			if !e.Type().IsRegular() {
				return nil
			}
			rel, err := filepath.Rel(storageDir, p)
			if err != nil {
				return err
			}
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			content[filepath.ToSlash(rel)] = b
			return nil
		})
		if err != nil {
			return Manifest{}, err
		}
	}
	// The model may be written to while it is copied; what was copied has
	// to replay on its own.
	idx, err := checkModel(content)
	if err != nil {
		return Manifest{}, fmt.Errorf("backup: the copied configuration does not replay: %w", err)
	}
	m := Manifest{Created: time.Now().UTC(), ModelIndex: idx}
	for name := range content {
		m.Files = append(m.Files, name)
	}
	sort.Strings(m.Files)

	var plain bytes.Buffer
	gz := gzip.NewWriter(&plain)
	tw := tar.NewWriter(gz)
	put := func(name string, b []byte) error {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(b)), ModTime: m.Created, Typeflag: tar.TypeReg}); err != nil {
			return err
		}
		_, err := tw.Write(b)
		return err
	}
	mj, _ := json.Marshal(m)
	if err := put(manifestName, mj); err != nil {
		return m, err
	}
	for _, name := range m.Files {
		if err := put(name, content[name]); err != nil {
			return m, err
		}
	}
	if err := tw.Close(); err != nil {
		return m, err
	}
	if err := gz.Close(); err != nil {
		return m, err
	}

	return m, seal(w, plain.Bytes(), pass)
}

// seal encrypts plain under pass and writes the archive.
func seal(w io.Writer, plain, pass []byte) error {
	h := header{KDF: "scrypt", N: kdfN, R: 8, P: 1, Salt: make([]byte, 16), Nonce: make([]byte, 12)}
	if _, err := rand.Read(h.Salt); err != nil {
		return err
	}
	if _, err := rand.Read(h.Nonce); err != nil {
		return err
	}
	key, err := deriveKey(pass, h)
	if err != nil {
		return err
	}
	aead, err := newAEAD(key)
	if err != nil {
		return err
	}
	hj, _ := json.Marshal(h)
	sealed := aead.Seal(nil, h.Nonce, plain, append([]byte(Magic), hj...))
	if _, err := io.WriteString(w, Magic); err != nil {
		return err
	}
	if _, err := w.Write(append(hj, '\n')); err != nil {
		return err
	}
	_, err = w.Write(sealed)
	return err
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// checkModel replays the configuration files of an archive in a scratch
// directory and returns the model's index.
func checkModel(content map[string][]byte) (int64, error) {
	tmp, err := os.MkdirTemp("", "testudo-backup-")
	if err != nil {
		return 0, err
	}
	defer os.RemoveAll(tmp)
	for _, f := range []string{"config/config.log", "config/config.snapshot"} {
		if b, ok := content[f]; ok {
			if err := os.WriteFile(filepath.Join(tmp, path.Base(f)), b, 0o600); err != nil {
				return 0, err
			}
		}
	}
	st, err := confstore.ReadState(tmp)
	if err != nil {
		return 0, err
	}
	return st.Index(), nil
}

// Open decrypts an archive and returns its manifest and files. A wrong
// passphrase and a changed archive give the same error.
func Open(r io.Reader, pass []byte) (Manifest, map[string][]byte, error) {
	br := bufio.NewReader(io.LimitReader(r, maxBody+maxHeader+int64(len(Magic))))
	magic := make([]byte, len(Magic))
	if _, err := io.ReadFull(br, magic); err != nil || string(magic) != Magic {
		return Manifest{}, nil, errors.New("backup: not a Testudo backup")
	}
	line, err := br.ReadSlice('\n')
	if err != nil || len(line) > maxHeader {
		return Manifest{}, nil, errors.New("backup: damaged header")
	}
	hj := bytes.TrimSuffix(line, []byte("\n"))
	var h header
	if err := json.Unmarshal(hj, &h); err != nil || len(h.Nonce) != 12 {
		return Manifest{}, nil, errors.New("backup: damaged header")
	}
	key, err := deriveKey(pass, h)
	if err != nil {
		return Manifest{}, nil, err
	}
	sealed, err := io.ReadAll(br)
	if err != nil {
		return Manifest{}, nil, err
	}
	aead, err := newAEAD(key)
	if err != nil {
		return Manifest{}, nil, err
	}
	plain, err := aead.Open(nil, h.Nonce, sealed, append([]byte(Magic), hj...))
	if err != nil {
		return Manifest{}, nil, errors.New("backup: wrong passphrase or the archive was changed")
	}
	gz, err := gzip.NewReader(bytes.NewReader(plain))
	if err != nil {
		return Manifest{}, nil, err
	}
	tr := tar.NewReader(io.LimitReader(gz, maxBody))
	out := map[string][]byte{}
	var m Manifest
	seenManifest := false
	for {
		th, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return Manifest{}, nil, err
		}
		name := th.Name
		if th.Typeflag != tar.TypeReg || th.Size > maxFile || path.Clean(name) != name || path.IsAbs(name) || strings.HasPrefix(name, "../") {
			return Manifest{}, nil, fmt.Errorf("backup: unexpected entry %q", name)
		}
		b, err := io.ReadAll(io.LimitReader(tr, maxFile))
		if err != nil {
			return Manifest{}, nil, err
		}
		if name == manifestName {
			if err := json.Unmarshal(b, &m); err != nil {
				return Manifest{}, nil, err
			}
			seenManifest = true
			continue
		}
		if !allowed(name) {
			return Manifest{}, nil, fmt.Errorf("backup: unexpected entry %q", name)
		}
		out[name] = b
	}
	if !seenManifest {
		return Manifest{}, nil, errors.New("backup: the archive has no manifest")
	}
	return m, out, nil
}

// Restore writes an archive into storageDir. The daemon must not run: the
// configuration store's lock is taken for the duration. A storage
// directory that holds a configuration already is refused unless force is
// set. Files of the node that the archive does not contain are left alone.
func Restore(r io.Reader, storageDir string, pass []byte, force bool) (Manifest, error) {
	m, content, err := Open(r, pass)
	if err != nil {
		return m, err
	}
	if _, err := checkModel(content); err != nil {
		return m, fmt.Errorf("backup: the archived configuration does not replay: %w", err)
	}
	cfgDir := filepath.Join(storageDir, "config")
	if fi, err := os.Stat(filepath.Join(cfgDir, "config.log")); err == nil && fi.Size() > 0 && !force {
		return m, errors.New("backup: this node has a configuration already; restore with --force to replace it")
	}
	// Taking the store's lock proves no daemon has it open.
	store, err := confstore.Open(cfgDir)
	if err != nil {
		if errors.Is(err, confstore.ErrLocked) {
			return m, errors.New("backup: the configuration is in use; stop testudo before restoring")
		}
		return m, err
	}
	defer store.Close()
	if err := os.MkdirAll(storageDir, 0o700); err != nil {
		return m, err
	}
	names := make([]string, 0, len(content))
	for name := range content {
		names = append(names, name)
	}
	sort.Strings(names)
	// A snapshot from before the archive would be replayed under its log:
	// the configuration is replaced as a whole.
	if _, ok := content["config/config.snapshot"]; !ok {
		_ = os.Remove(filepath.Join(cfgDir, "config.snapshot"))
	}
	for _, name := range names {
		dst := filepath.Join(storageDir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			return m, err
		}
		tmp := dst + ".restore"
		if err := os.WriteFile(tmp, content[name], 0o600); err != nil {
			return m, err
		}
		if err := os.Rename(tmp, dst); err != nil {
			return m, err
		}
	}
	return m, nil
}
