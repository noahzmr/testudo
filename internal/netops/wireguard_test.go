package netops

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSyncNetplanReplacesPeersPreservesKey(t *testing.T) {
	dir := t.TempDir()
	old := netplanDir
	netplanDir = dir
	t.Cleanup(func() { netplanDir = old })

	path := filepath.Join(dir, "60-testudo-wg.yaml")
	initial := "# Managed by Testudo - WireGuard interface config.\n" +
		"network:\n  version: 2\n  tunnels:\n    wg0:\n" +
		"      mode: wireguard\n      addresses: [10.8.0.1/24]\n      port: 51820\n" +
		"      key: SUPERSECRETPRIVATEKEY=\n" +
		"      peers:\n        - keys:\n            public: OLDPEER\n          allowed-ips: [10.8.0.2/32]\n"
	if err := os.WriteFile(path, []byte(initial), 0o600); err != nil {
		t.Fatal(err)
	}

	w := &Writer{AllowWrites: true}
	err := w.syncNetplanDirect(path, []NetplanPeerWire{
		{PublicKey: "NEWPEER", AllowedIPs: []string{"10.8.0.9/32"}, Keepalive: 25},
	})
	if err != nil {
		t.Fatal(err)
	}
	out, _ := os.ReadFile(path)
	s := string(out)
	// Interface block + private key preserved.
	if !strings.Contains(s, "key: SUPERSECRETPRIVATEKEY=") {
		t.Fatalf("private key must be preserved:\n%s", s)
	}
	if !strings.Contains(s, "port: 51820") || !strings.Contains(s, "addresses: [10.8.0.1/24]") {
		t.Fatalf("interface settings must be preserved:\n%s", s)
	}
	// Peers replaced.
	if strings.Contains(s, "OLDPEER") {
		t.Fatalf("old peer must be gone:\n%s", s)
	}
	if !strings.Contains(s, "public: NEWPEER") || !strings.Contains(s, "allowed-ips: [10.8.0.9/32]") {
		t.Fatalf("new peer must be present:\n%s", s)
	}
	// Perms stay 0600.
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Fatalf("netplan perms = %v want 0600", fi.Mode().Perm())
	}
}

func TestSyncNetplanIgnoresUnmanagedFile(t *testing.T) {
	dir := t.TempDir()
	old := netplanDir
	netplanDir = dir
	t.Cleanup(func() { netplanDir = old })

	path := filepath.Join(dir, "01-operator.yaml")
	operator := "network:\n  version: 2\n  tunnels:\n    wg0:\n      mode: wireguard\n      key: OPKEY\n"
	if err := os.WriteFile(path, []byte(operator), 0o600); err != nil {
		t.Fatal(err)
	}
	w := &Writer{AllowWrites: true}
	if err := w.syncNetplanDirect(path, []NetplanPeerWire{{PublicKey: "X"}}); err != nil {
		t.Fatal(err)
	}
	out, _ := os.ReadFile(path)
	if string(out) != operator {
		t.Fatalf("operator file must be untouched, got:\n%s", out)
	}
}

func TestSyncNetplanMissingFileIsNoop(t *testing.T) {
	dir := t.TempDir()
	old := netplanDir
	netplanDir = dir
	t.Cleanup(func() { netplanDir = old })

	w := &Writer{AllowWrites: true}
	if err := w.syncNetplanDirect(filepath.Join(dir, "nope.yaml"), []NetplanPeerWire{{PublicKey: "X"}}); err != nil {
		t.Fatalf("missing netplan should be a no-op, got %v", err)
	}
}

func TestListNetplanDirect(t *testing.T) {
	dir := t.TempDir()
	old := netplanDir
	netplanDir = dir
	t.Cleanup(func() { netplanDir = old })

	if err := os.WriteFile(filepath.Join(dir, "01-op.yaml"), []byte("network:\n  version: 2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "60-testudo-wg.yaml"), []byte("# Managed by Testudo\nnetwork:\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("ignore me"), 0o600); err != nil {
		t.Fatal(err)
	}

	w := &Writer{}
	body, err := w.listNetplanDirect()
	if err != nil {
		t.Fatal(err)
	}
	var files []NetplanFile
	if err := json.Unmarshal(body, &files); err != nil {
		t.Fatal(err)
	}
	if len(files) != 2 {
		t.Fatalf("expected 2 yaml files (txt ignored), got %d: %+v", len(files), files)
	}
	// Sorted by name: 01-op first, then 60-testudo.
	if files[0].Name != "01-op.yaml" || files[1].Name != "60-testudo-wg.yaml" {
		t.Fatalf("unexpected order: %+v", files)
	}
	if files[0].Managed {
		t.Fatal("operator file must not be marked managed")
	}
	if !files[1].Managed {
		t.Fatal("testudo file must be marked managed")
	}
}

func TestSyncNetplanRejectsBadPath(t *testing.T) {
	w := &Writer{AllowWrites: true}
	if err := w.syncNetplanDirect("/tmp/evil.yaml", nil); err == nil {
		t.Fatal("path outside /etc/netplan (or the test dir) must be rejected")
	}
}
