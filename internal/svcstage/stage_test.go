package svcstage

import (
	"context"
	"testing"

	"github.com/noahzmr/testudo/internal/confstore"
	"github.com/noahzmr/testudo/internal/netops"
)

// TestNoServicesNeedNoWrites: with nothing to run and writes turned off,
// the stage has nothing to do and says so without an error.
func TestNoServicesNeedNoWrites(t *testing.T) {
	store, err := confstore.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	dir := t.TempDir()
	s := &Stage{Runner: &netops.Writer{AllowWrites: false}, Dir: dir, RunDir: dir}
	raw, err := s.Render(store.Current())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := s.Check(ctx, raw); err != nil {
		t.Fatal(err)
	}
	if err := s.Apply(ctx, raw); err != nil {
		t.Fatalf("apply of no services with writes off: %v", err)
	}
	if err := s.Healthy(ctx); err != nil {
		t.Fatal(err)
	}
}
