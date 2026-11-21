package config

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultStorage(t *testing.T) {
	env := func(v string) func(string) string { return func(string) string { return v } }
	yes := func(string) bool { return true }
	no := func(string) bool { return false }
	if got := defaultStorage(env("/srv/t"), 0, yes); got != "/srv/t" {
		t.Errorf("TESTUDO_STORAGE: %s", got)
	}
	if got := defaultStorage(env(""), 0, yes); got != SystemStorage {
		t.Errorf("root with an installed service: %s", got)
	}
	for _, tc := range []struct {
		euid   int
		exists func(string) bool
	}{{0, no}, {1000, yes}} {
		if got := defaultStorage(env(""), tc.euid, tc.exists); !strings.HasSuffix(got, string(filepath.Separator)+".testudo") {
			t.Errorf("euid %d: %s", tc.euid, got)
		}
	}
}
