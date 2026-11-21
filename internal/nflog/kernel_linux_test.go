package nflog

import (
	"net"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/noahzmr/testudo/internal/testnet"
)

// TestLoggedPacketsOnARealKernel: a rule that logs to the group, a packet
// it matches, and the entry the reader gets.
func TestLoggedPacketsOnARealKernel(t *testing.T) {
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("nft is not installed")
	}
	if testnet.Isolate(t) {
		return
	}
	if out, err := exec.Command("sh", "-ec", `ip link set lo up
nft -f - <<'EOF'
table inet tlog {
	chain input {
		type filter hook input priority filter; policy accept;
		udp dport 9999 log prefix "t:test-rule" group 7
	}
}
EOF`).CombinedOutput(); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	fd, err := Open(Group)
	testnet.Must(t, err)
	r := NewReader(fd)
	defer r.Close()
	got := make(chan Entry, 1)
	go func() {
		for {
			evs, err := r.Read()
			if err != nil {
				return
			}
			for _, e := range evs {
				if strings.HasPrefix(e.Prefix, "t:test-rule") {
					got <- e
					return
				}
			}
		}
	}()
	c, err := net.Dial("udp", "127.0.0.1:9999")
	testnet.Must(t, err)
	defer c.Close()
	deadline := time.After(10 * time.Second)
	for {
		c.Write([]byte("ping"))
		select {
		case e := <-got:
			if e.DstPort != 9999 || e.ProtoName() != "udp" || e.Dst.String() != "127.0.0.1" || e.InDev == 0 {
				t.Errorf("entry: %+v", e)
			}
			return
		case <-deadline:
			t.Fatal("no entry from the log group")
		case <-time.After(200 * time.Millisecond):
		}
	}
}
