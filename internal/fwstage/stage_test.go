package fwstage

import (
	"context"
	"errors"
	"testing"

	"github.com/noahzmr/testudo/internal/confstore"
	"github.com/noahzmr/testudo/internal/model"
)

// deniedRunner is a process without network privileges.
type deniedRunner struct{ writes bool }

var errDenied = errors.New("nft: netlink: Error: cache initialization failed: Operation not permitted")

func (r deniedRunner) WritesAllowed() bool                       { return r.writes }
func (deniedRunner) NftCheck(string) error                       { return errDenied }
func (deniedRunner) NftApply(string) error                       { return errDenied }
func (deniedRunner) NftListTable(string, string) ([]byte, error) { return nil, errDenied }

func render(t *testing.T, s *Stage, withPolicy bool) []byte {
	t.Helper()
	store, err := confstore.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if withPolicy {
		if _, err := store.Create(context.Background(), "a", &model.FirewallPolicy{Meta: model.Meta{Name: "p"}, DefaultDeny: true}); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := s.Render(store.Current())
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// TestAModelWithoutPolicyNeedsNoPrivileges: a node that cannot reach
// nftables still takes a model that filters nothing (users, roles, the
// first administrator), and refuses one that has a firewall policy.
func TestAModelWithoutPolicyNeedsNoPrivileges(t *testing.T) {
	ctx := context.Background()
	for _, writes := range []bool{true, false} {
		s := &Stage{Runner: deniedRunner{writes: writes}}
		empty := render(t, s, false)
		if err := s.Check(ctx, empty); err != nil {
			t.Errorf("writes=%v: check of a model without policy: %v", writes, err)
		}
		if err := s.Apply(ctx, empty); err != nil {
			t.Errorf("writes=%v: apply of a model without policy: %v", writes, err)
		}
		if err := s.Healthy(ctx); err != nil {
			t.Errorf("writes=%v: health of a model without policy: %v", writes, err)
		}

		policy := render(t, s, true)
		if err := s.Check(ctx, policy); err == nil {
			t.Errorf("writes=%v: a firewall policy passed the check without nftables", writes)
		}
		if err := s.Apply(ctx, policy); err == nil {
			t.Errorf("writes=%v: a firewall policy was applied without nftables", writes)
		}
	}
}
