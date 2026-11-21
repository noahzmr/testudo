package lbrender

import (
	"strings"
	"testing"

	"github.com/noahzmr/testudo/internal/model"
)

func TestBackendsAtOtherSitesTakeOver(t *testing.T) {
	site := func(n int) model.Ref[model.Site] { return model.Ref[model.Site]{ID: id(n)} }
	multi := &model.LBBackendPool{Meta: meta(25, "multi"), Algorithm: "weighted_round_robin",
		HealthCheck: model.LBHealthCheck{Type: "http", Path: "/healthz"},
		Backends: []model.LBBackend{{Address: "10.1.0.10:80", Site: site(1)}, {Address: "10.1.0.11:80"},
			{Address: "10.2.0.10:80", Site: site(2)}}}
	svc := service(30, "http", "http", 80)
	svc.DefaultPool = pool(25)
	st := build(t, &model.Site{Meta: meta(1, "hq")}, &model.Site{Meta: meta(2, "branch")}, multi, svc)

	o := opts()
	o.SiteID = id(1)
	res, err := Render(st, o)
	if err != nil {
		t.Fatal(err)
	}
	dyn := res.Files[DynamicFile]
	for _, want := range []string{
		"failover:\n                fallback: pool-multi-000000-remote\n                service: pool-multi-000000-local",
		"-local:\n            loadBalancer:",
		"url: http://10.1.0.10:80", "url: http://10.1.0.11:80",
	} {
		if !strings.Contains(dyn, want) {
			t.Errorf("hq lacks %q in:\n%s", want, dyn)
		}
	}
	local := dyn[strings.Index(dyn, "-local:"):strings.Index(dyn, "-remote:")]
	if strings.Contains(local, "10.2.0.10") {
		t.Error("hq's own pool contains the branch backend")
	}
	// At the branch it is the other way round.
	o.SiteID = id(2)
	res, _ = Render(st, o)
	dyn = res.Files[DynamicFile]
	local = dyn[strings.Index(dyn, "-local:"):strings.Index(dyn, "-remote:")]
	if !strings.Contains(local, "10.2.0.10") || strings.Contains(local, "10.1.0.10") {
		t.Errorf("branch's own pool:\n%s", local)
	}
	// Failing over needs a health check that can notice.
	multi.HealthCheck = model.LBHealthCheck{Type: "tcp"}
	st = build(t, &model.Site{Meta: meta(1, "hq")}, &model.Site{Meta: meta(2, "branch")}, multi, svc)
	o.SiteID = id(1)
	if _, err := Render(st, o); err == nil || !strings.Contains(err.Error(), "HTTP health check") {
		t.Errorf("failover without an HTTP health check: %v", err)
	}
}
