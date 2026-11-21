package engine

import (
	"context"
	"testing"
	"time"

	"github.com/noahzmr/testudo/internal/config"
	"github.com/noahzmr/testudo/internal/confstore"
	"github.com/noahzmr/testudo/internal/model"
)

// TestSettingsSurviveTheTripThroughTheModel: what settings.json held comes
// back the same from the model object it becomes, and the node's own
// switch is not the model's.
func TestSettingsSurviveTheTripThroughTheModel(t *testing.T) {
	in := config.DefaultThresholds()
	in.PacketLossPct, in.RTTMs, in.IncidentCooldown = 3.5, 90, 5*time.Minute
	in.IPFIXEnabled, in.IPFIXEndpoint, in.IPFIXIntervalSec = true, "collector:4739", 10
	in.SentryDSN, in.GuacamoleAPIPassword, in.MaxMindLicenseKey = "https://k@sentry.example/1", "pw", "lic"
	in.AllowNetopsWrite = true

	ns := toModel(in)
	if ns.DNSLatencyMs != 0 || ns.JitterMs != 0 {
		t.Errorf("defaults were written into the model: %+v", ns)
	}
	out := config.DefaultThresholds()
	out.AllowNetopsWrite = true
	fromModel(&out, ns)
	if out != in {
		t.Errorf("round trip:\n got %+v\nwant %+v", out, in)
	}
	// An empty object is the built-in defaults, whatever ran before.
	fromModel(&out, &model.NodeSettings{})
	want := config.DefaultThresholds()
	want.AllowNetopsWrite = true
	if out != want {
		t.Errorf("an empty object:\n got %+v\nwant %+v", out, want)
	}
}

// TestTheNarrowestSettingsApply: a node's own settings win over its site's,
// which win over the global ones; another node's do not apply.
func TestTheNarrowestSettingsApply(t *testing.T) {
	store, err := confstore.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	mk := func(e model.Entity) string {
		t.Helper()
		o, err := store.Create(ctx, "t", e)
		if err != nil {
			t.Fatal(err)
		}
		return o.GetMeta().ID
	}
	site := mk(&model.Site{Meta: model.Meta{Name: "hq"}})
	n1 := mk(&model.ClusterNode{Meta: model.Meta{Name: "fw1"}, Site: model.Ref[model.Site]{ID: site}, Hostname: "fw1", Address: "10.0.0.1"})
	n2 := mk(&model.ClusterNode{Meta: model.Meta{Name: "fw2"}, Site: model.Ref[model.Site]{ID: site}, Hostname: "fw2", Address: "10.0.0.2"})
	mk(&model.NodeSettings{Meta: model.Meta{Name: "all"}, RTTMs: 100})
	mk(&model.NodeSettings{Meta: model.Meta{Name: "hq", Scope: model.SiteScope(site)}, RTTMs: 200})
	mk(&model.NodeSettings{Meta: model.Meta{Name: "fw1", Scope: model.NodeScope(n1)}, RTTMs: 300})
	st := store.Current()
	if got := nodeSettings(st, site, n1).RTTMs; got != 300 {
		t.Errorf("fw1: %v", got)
	}
	if got := nodeSettings(st, site, n2).RTTMs; got != 200 {
		t.Errorf("fw2: %v", got)
	}
	if got := nodeSettings(st, "", "").RTTMs; got != 100 {
		t.Errorf("a node outside the site: %v", got)
	}
}
