//go:build linux

package fwrender

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/noahzmr/testudo/internal/testnet"
)

// TestGoldenRulesetLoadsIntoAKernel gives the ruleset behind the golden file
// to nft: a renderer whose output the kernel refuses is worth nothing,
// however stable its text is.
func TestGoldenRulesetLoadsIntoAKernel(t *testing.T) {
	if testnet.Isolate(t) {
		return
	}
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("nft is not installed")
	}
	path := filepath.Join(t.TempDir(), "site.nft")
	if err := os.WriteFile(path, []byte(full(t).render(opts())), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"-c", "-f", path}, {"-f", path}, {"-f", path}} { // twice: reload replaces
		if out, err := exec.Command("nft", args...).CombinedOutput(); err != nil {
			t.Fatalf("nft %s: %v\n%s", strings.Join(args, " "), err, out)
		}
	}
	out, _ := exec.Command("nft", "list", "table", "inet", "testudo").CombinedOutput()
	for _, want := range []string{"dnat ip to 192.0.2.10:8443", "dnat ip6 to [2001:db8::10]:8443", "snat ip to 203.0.113.6",
		"masquerade", "fib saddr . iif oif missing", "ct timeout set", "@a4_blocklist"} {
		if !strings.Contains(string(out), want) {
			t.Errorf("the loaded table lacks %q", want)
		}
	}
	if t.Failed() {
		t.Logf("%s", out)
	}
}
