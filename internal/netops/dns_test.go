package netops

import (
	"os"
	"path/filepath"
	"testing"
)

// TestInspectResolvConf_PlainFile: a regular file is writable, not a stub.
func TestInspectResolvConf_PlainFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "resolv.conf")
	if err := os.WriteFile(path, []byte("nameserver 1.1.1.1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	rc := InspectResolvConf(path)
	if rc.Symlink || rc.Stub {
		t.Fatalf("plain file misdetected: %+v", rc)
	}
}

// TestInspectResolvConf_StubSymlink: a symlink into /run/systemd/resolve is a
// resolved-managed stub and must be flagged.
func TestInspectResolvConf_StubSymlink(t *testing.T) {
	dir := t.TempDir()
	// Simulate the systemd-resolved layout under a temp root.
	runDir := filepath.Join(dir, "run", "systemd", "resolve")
	if err := os.MkdirAll(runDir, 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(runDir, "stub-resolv.conf")
	if err := os.WriteFile(target, []byte("nameserver 127.0.0.53\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "resolv.conf")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	rc := InspectResolvConf(link)
	if !rc.Symlink {
		t.Fatalf("symlink not detected: %+v", rc)
	}
	if !rc.Stub {
		t.Fatalf("stub not detected for target %q", rc.LinkTarget)
	}
}

// TestInspectResolvConf_NonStubSymlink: a symlink to an ordinary file (e.g.
// NetworkManager's own copy) is editable, not a resolved stub.
func TestInspectResolvConf_NonStubSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real-resolv.conf")
	if err := os.WriteFile(target, []byte("nameserver 9.9.9.9\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "resolv.conf")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	rc := InspectResolvConf(link)
	if !rc.Symlink {
		t.Fatalf("symlink not detected: %+v", rc)
	}
	if rc.Stub {
		t.Fatalf("ordinary symlink wrongly flagged as stub: %+v", rc)
	}
}

func TestInspectResolvConf_Missing(t *testing.T) {
	rc := InspectResolvConf(filepath.Join(t.TempDir(), "nope.conf"))
	if rc.Symlink || rc.Stub {
		t.Fatalf("missing file should be zero-value: %+v", rc)
	}
}
