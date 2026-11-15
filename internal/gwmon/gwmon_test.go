package gwmon

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/noahzmr/testudo/internal/model"
)

func TestHysteresis(t *testing.T) {
	answers := map[string]bool{"192.0.2.1": true, "192.0.2.2": true}
	var probeErr error
	m := &Monitor{Probe: func(_ context.Context, addr string) (bool, error) { return answers[addr], probeErr }}
	gws := []*model.Gateway{
		{Meta: model.Meta{ID: "a"}, Enabled: true, Monitor: "192.0.2.1"},
		{Meta: model.Meta{ID: "b"}, Enabled: true, Monitor: "192.0.2.2"},
		{Meta: model.Meta{ID: "c"}, Enabled: true},                        // not monitored
		{Meta: model.Meta{ID: "d"}, Enabled: false, Monitor: "192.0.2.4"}, // disabled
	}
	now := time.Unix(0, 0)
	round := func() bool { now = now.Add(5 * time.Second); return m.Check(context.Background(), gws, now) }

	if round() || len(m.Down()) != 0 || len(m.Status()) != 2 {
		t.Fatalf("healthy start: down=%v status=%v", m.Down(), m.Status())
	}
	// One and two failures change nothing; the third takes the gateway down.
	answers["192.0.2.1"] = false
	if round() || round() {
		t.Fatal("went down before the threshold")
	}
	if !round() || !m.Down()["a"] || m.Down()["b"] {
		t.Fatalf("after three failures: %v", m.Down())
	}
	// A single answer in between does not bring it back.
	answers["192.0.2.1"] = true
	if round() || !m.Down()["a"] {
		t.Fatal("came back after one success")
	}
	answers["192.0.2.1"] = false
	round()
	answers["192.0.2.1"] = true
	if round() || round() || !m.Down()["a"] {
		t.Fatal("the success streak was not reset by a failure")
	}
	if !round() || m.Down()["a"] {
		t.Fatalf("after three successes: %v", m.Down())
	}
	// When probing itself fails, nothing is concluded.
	probeErr = errors.New("permission denied")
	answers["192.0.2.2"] = false
	for i := 0; i < 5; i++ {
		round()
	}
	if m.Down()["b"] || m.Status()["b"].Error == "" {
		t.Errorf("a probe error took a gateway down: %+v", m.Status()["b"])
	}
	// A gateway that was down and is removed counts as a change.
	probeErr = nil
	for i := 0; i < 3; i++ {
		round()
	}
	if !m.Down()["b"] {
		t.Fatal("precondition: b should be down")
	}
	gws = gws[:1]
	if !round() || len(m.Status()) != 1 {
		t.Errorf("after removing a down gateway: %v", m.Status())
	}
}
