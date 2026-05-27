package doctor

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestClassify(t *testing.T) {
	cases := map[string]ErrorClass{
		"":                                     ClassNone,
		"timeout":                              ClassTimeout,
		"i/o deadline exceeded":                ClassTimeout,
		"*":                                    ClassTimeout,
		"socket: operation not permitted":      ClassPermission,
		"dial: permission denied":              ClassPermission,
		"connect: no route to host":            ClassNoRoute,
		"network is unreachable":               ClassNoRoute,
		"connection refused":                   ClassRefused,
		"lookup one.one.one.one: no such host": ClassDNS,
		"something weird happened":             ClassUnknown,
	}
	for in, want := range cases {
		if got := classify(in); got != want {
			t.Errorf("classify(%q)=%q want %q", in, got, want)
		}
	}
}

func TestIsRoutable(t *testing.T) {
	cases := map[string]bool{
		"192.168.1.20": true,
		"8.8.8.8":      true,
		"2001:db8::1":  true,
		"127.0.0.1":    false, // loopback
		"::1":          false, // loopback
		"169.254.1.5":  false, // ipv4 link-local
		"fe80::1":      false, // ipv6 link-local
		"0.0.0.0":      false, // unspecified
	}
	for in, want := range cases {
		ip := ipFromCIDR(in)
		if got := isRoutable(ip); got != want {
			t.Errorf("isRoutable(%q)=%v want %v", in, got, want)
		}
	}
}

func TestIPFromCIDR(t *testing.T) {
	if ip := ipFromCIDR("192.168.1.20/24"); ip == nil || ip.String() != "192.168.1.20" {
		t.Fatalf("CIDR parse failed: %v", ip)
	}
	if ip := ipFromCIDR("10.0.0.1"); ip == nil || ip.String() != "10.0.0.1" {
		t.Fatalf("bare IP parse failed: %v", ip)
	}
	if ip := ipFromCIDR("not-an-ip"); ip != nil {
		t.Fatalf("garbage should yield nil, got %v", ip)
	}
}

// captiveEnv builds an Env pointed at the given server URL with one up link so
// the captive check actually runs.
func captiveEnv(url string) *Env {
	opts := DefaultOptions()
	opts.CaptiveURL = url
	opts.CheckTimeout = time.Second
	return &Env{
		HTTP:     defaultHTTPClient(opts.CheckTimeout),
		Opts:     opts,
		Findings: &Findings{UpLinks: []string{"eth0"}},
	}
}

func TestCaptiveCheck_CleanEgress(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent) // 204, empty body - the healthy signal
	}))
	defer srv.Close()
	res := captiveCheck{}.Run(context.Background(), captiveEnv(srv.URL))
	if res.Status != StatusPass {
		t.Fatalf("204 should pass, got %v (%s)", res.Status, res.Summary)
	}
}

func TestCaptiveCheck_PortalRedirect(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", "http://login.hotel-wifi.example/portal")
		w.WriteHeader(http.StatusFound) // 302 to a login page
	}))
	defer srv.Close()
	res := captiveCheck{}.Run(context.Background(), captiveEnv(srv.URL))
	if res.Status != StatusWarn {
		t.Fatalf("302 should warn (captive portal), got %v", res.Status)
	}
	if res.Detail == "" {
		t.Fatalf("expected redirect target in detail")
	}
}

func TestCaptiveCheck_Skipped(t *testing.T) {
	env := captiveEnv("http://unused.example")
	env.Opts.SkipCaptive = true
	if res := (captiveCheck{}).Run(context.Background(), env); res.Status != StatusSkip {
		t.Fatalf("--no-captive should skip, got %v", res.Status)
	}
	// And with no up link.
	env2 := captiveEnv("http://unused.example")
	env2.Findings.UpLinks = nil
	if res := (captiveCheck{}).Run(context.Background(), env2); res.Status != StatusSkip {
		t.Fatalf("no link should skip captive check, got %v", res.Status)
	}
}
