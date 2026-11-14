package netops

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestNftRequestsAreConfinedToThreeModes(t *testing.T) {
	if res := RunNft(NftRequest{Mode: "flush"}); !strings.Contains(res.Error, "unknown nft mode") && !strings.Contains(res.Error, "not installed") {
		t.Errorf("unknown mode: %+v", res)
	}
	for _, bad := range []NftRequest{
		{Mode: NftList, Family: "inet", Table: "testudo; flush ruleset"},
		{Mode: NftList, Family: "inet -a", Table: "testudo"},
		{Mode: NftList, Family: "", Table: "testudo"},
	} {
		if res := RunNft(bad); !strings.Contains(res.Error, "bad table name") && !strings.Contains(res.Error, "not installed") {
			t.Errorf("%+v was not refused: %+v", bad, res)
		}
	}
}

// An unprivileged process must not conclude that it can load rulesets, or
// the engine would pick a path on which every change fails.
func TestNftAvailabilityNeedsRealKernelAccess(t *testing.T) {
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("nft is not installed")
	}
	if os.Geteuid() == 0 {
		t.Skip("root can load rulesets; the unprivileged case is what is tested")
	}
	if (&Writer{}).NftAvailable() {
		t.Error("an unprivileged process reports that it can load nftables rulesets")
	}
}

func TestNftApplyRespectsTheWriteGate(t *testing.T) {
	if err := (&Writer{AllowWrites: false}).NftApply("table inet x\n"); err == nil || !strings.Contains(err.Error(), "writes are disabled") {
		t.Errorf("err = %v", err)
	}
}
