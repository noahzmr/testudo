package netops

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

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
