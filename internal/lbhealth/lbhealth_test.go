package lbhealth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/noahzmr/testudo/internal/model"
)

func TestBackendChangesStateAfterAStreak(t *testing.T) {
	fail := map[string]bool{}
	m := &Monitor{Probe: func(_ context.Context, addr string, _ model.LBHealthCheck) error {
		if fail[addr] {
			return errors.New("refused")
		}
		return nil
	}}
	pools := map[string]*model.LBBackendPool{
		"p": {Backends: []model.LBBackend{{Address: "10.0.0.1:80"}, {Address: "10.0.0.2:80"}}, HealthCheck: model.LBHealthCheck{Type: "tcp"}},
		"q": {Backends: []model.LBBackend{{Address: "10.0.0.9:80"}}, HealthCheck: model.LBHealthCheck{Type: "none"}},
	}
	ctx, now := context.Background(), time.Unix(1000, 0)
	if m.Check(ctx, pools, now) || len(m.Down()) != 0 {
		t.Fatal("healthy backends reported a change")
	}
	if _, checked := m.Status()["10.0.0.9:80"]; checked {
		t.Error("a pool without a check was probed")
	}
	fail["10.0.0.1:80"] = true
	if m.Check(ctx, pools, now) {
		t.Error("one failed probe already changed the state")
	}
	fail["10.0.0.1:80"] = false
	m.Check(ctx, pools, now) // the streak is broken
	fail["10.0.0.1:80"] = true
	m.Check(ctx, pools, now)
	if !m.Check(ctx, pools, now) || !m.Down()["10.0.0.1:80"] || m.Down()["10.0.0.2:80"] {
		t.Errorf("after two failures in a row: %v", m.Down())
	}
	if m.Status()["10.0.0.1:80"].Error != "refused" {
		t.Errorf("status: %+v", m.Status()["10.0.0.1:80"])
	}
	fail["10.0.0.1:80"] = false
	m.Check(ctx, pools, now)
	if !m.Check(ctx, pools, now) || len(m.Down()) != 0 {
		t.Errorf("after two successes in a row: %v", m.Down())
	}
	// A backend that is down and then removed from the model is a change.
	fail["10.0.0.2:80"] = true
	m.Check(ctx, pools, now)
	m.Check(ctx, pools, now)
	pools["p"].Backends = pools["p"].Backends[:1]
	if !m.Check(ctx, pools, now) || len(m.Down()) != 0 {
		t.Errorf("after removing the failed backend: %v", m.Down())
	}
}
