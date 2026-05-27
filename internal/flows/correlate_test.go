package flows

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// waitFor polls until cond is true or the deadline elapses. Reverse lookups
// resolve asynchronously, so tests can't assume the result is ready on the
// first Lookup after a miss.
func waitFor(cond func() bool) bool {
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(2 * time.Millisecond)
	}
	return cond()
}

func TestDNSCacheReverseResolvesMiss(t *testing.T) {
	c := NewDNSCache()
	c.lookupAddr = func(_ context.Context, addr string) ([]string, error) {
		if addr == "93.184.216.34" {
			return []string{"example.com."}, nil // note trailing dot
		}
		return nil, errors.New("no PTR")
	}

	// First Lookup misses and kicks off the background PTR query.
	if got := c.Lookup("93.184.216.34"); got != "" {
		t.Fatalf("expected empty on first (miss) lookup, got %q", got)
	}

	if !waitFor(func() bool { return c.Lookup("93.184.216.34") == "example.com" }) {
		t.Fatalf("reverse lookup never populated cache: got %q", c.Lookup("93.184.216.34"))
	}
}

func TestDNSCacheForwardWinsOverReverse(t *testing.T) {
	c := NewDNSCache()
	c.lookupAddr = func(_ context.Context, _ string) ([]string, error) {
		return []string{"ptr-name.example."}, nil
	}
	c.Record("friendly.example.com", []string{"10.20.30.40"})

	// Private but explicitly recorded: forward name must be returned and the
	// reverse path must not run (the IP is already known).
	if got := c.Lookup("10.20.30.40"); got != "friendly.example.com" {
		t.Fatalf("forward name should win, got %q", got)
	}
}

func TestDNSCacheSkipsNonRoutable(t *testing.T) {
	var calls int32
	c := NewDNSCache()
	c.lookupAddr = func(_ context.Context, _ string) ([]string, error) {
		atomic.AddInt32(&calls, 1)
		return []string{"nope."}, nil
	}

	for _, ip := range []string{"127.0.0.1", "::1", "0.0.0.0", "169.254.1.1", "224.0.0.1"} {
		if got := c.Lookup(ip); got != "" {
			t.Fatalf("%s should not resolve, got %q", ip, got)
		}
	}
	time.Sleep(50 * time.Millisecond)
	if n := atomic.LoadInt32(&calls); n != 0 {
		t.Fatalf("expected no PTR queries for non-routable addrs, got %d", n)
	}
}

func TestDNSCacheReverseDisabled(t *testing.T) {
	var calls int32
	c := NewDNSCache()
	c.SetReverseEnabled(false)
	c.lookupAddr = func(_ context.Context, _ string) ([]string, error) {
		atomic.AddInt32(&calls, 1)
		return []string{"x."}, nil
	}

	c.Lookup("8.8.8.8")
	time.Sleep(50 * time.Millisecond)
	if n := atomic.LoadInt32(&calls); n != 0 {
		t.Fatalf("reverse disabled: expected 0 PTR queries, got %d", n)
	}
}

func TestDNSCacheNegativeCacheSuppressesRetries(t *testing.T) {
	var calls int32
	c := NewDNSCache()
	c.lookupAddr = func(_ context.Context, _ string) ([]string, error) {
		atomic.AddInt32(&calls, 1)
		return nil, errors.New("nxdomain")
	}

	// Several misses in a row should produce exactly one query within the
	// negative-cache TTL.
	for i := 0; i < 5; i++ {
		c.Lookup("203.0.113.7")
		time.Sleep(10 * time.Millisecond)
	}
	if n := atomic.LoadInt32(&calls); n != 1 {
		t.Fatalf("expected 1 PTR query under negative cache, got %d", n)
	}
}
