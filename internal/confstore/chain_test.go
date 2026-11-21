package confstore

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/noahzmr/testudo/internal/model"
)

// TestTheLogIsChained: every record carries the hash of the one before;
// the chain verifies, survives compaction and a restart, a second store
// applying the same records ends on the same hash, and a record rewritten
// in the file is found.
func TestTheLogIsChained(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	var recs []Record
	for _, name := range []string{"a", "b", "c", "d"} {
		obj, err := s.Create(ctx, "alice", &model.Alias{Meta: model.Meta{Name: name}, Type: "host", Entries: []string{"192.0.2.1"}})
		if err != nil {
			t.Fatal(err)
		}
		_ = obj
	}
	if n, broken, err := VerifyLog(dir); err != nil || n != 4 || broken != 0 {
		t.Fatalf("verify: %d %d %v", n, broken, err)
	}
	head := s.Current().hash

	// Another member applying the same records gets the same chain.
	other, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	recs, err = s.History(0, 10)
	if err != nil {
		t.Fatal(err)
	}
	for i := len(recs) - 1; i >= 0; i-- {
		if err := other.ApplyReplicated(recs[i]); err != nil {
			t.Fatal(err)
		}
	}
	if other.Current().hash != head {
		t.Errorf("another member's chain head %s, want %s", other.Current().hash, head)
	}

	// Compaction keeps the head; records after it chain on.
	if err := s.Compact(1); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Create(ctx, "alice", &model.Alias{Meta: model.Meta{Name: "e"}, Type: "host", Entries: []string{"192.0.2.2"}}); err != nil {
		t.Fatal(err)
	}
	if n, broken, err := VerifyLog(dir); err != nil || broken != 0 || n == 0 {
		t.Errorf("verify after compaction: %d %d %v", n, broken, err)
	}
	head = s.Current().hash
	s.Close()
	if s, err = Open(dir); err != nil {
		t.Fatal(err)
	}
	if s.Current().hash != head {
		t.Errorf("after a restart the head is %s, want %s", s.Current().hash, head)
	}
	s.Close()

	// Someone rewrites a record in the file.
	path := filepath.Join(dir, "config.log")
	data, _ := os.ReadFile(path)
	if err := os.WriteFile(path, bytes.Replace(data, []byte(`"alice"`), []byte(`"mallory"`), 1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, broken, _ := VerifyLog(dir); broken == 0 {
		t.Error("a rewritten record was not found")
	}
}
