//go:build linux

package privsep

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
)

// TestDropPrivilegesSubprocess runs the irreversible drop/seccomp sequence in a
// re-exec'd child (it can't run in-process without hobbling the test runner)
// and asserts the observable result: NO_NEW_PRIVS set, no effective caps, the
// seccomp filter installed, and a blocked syscall (ptrace) refused with EPERM.
func TestDropPrivilegesSubprocess(t *testing.T) {
	if os.Getenv("PRIVSEP_DROP_CHILD") == "1" {
		runDropChild() // exits the process
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestDropPrivilegesSubprocess", "-test.v")
	cmd.Env = append(os.Environ(), "PRIVSEP_DROP_CHILD=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("drop child failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "DROP-OK") {
		t.Fatalf("drop child did not confirm success:\n%s", out)
	}
}

func runDropChild() {
	fail := func(format string, a ...any) {
		fmt.Fprintf(os.Stderr, "DROP-FAIL: "+format+"\n", a...)
		os.Exit(2)
	}

	if err := DropPrivileges(); err != nil {
		fail("DropPrivileges: %v", err)
	}
	if nnp, err := NoNewPrivs(); err != nil || !nnp {
		fail("NoNewPrivs=%v err=%v", nnp, err)
	}
	if caps, err := EffectiveCaps(); err != nil || caps != 0 {
		fail("EffectiveCaps=%#x err=%v (want 0)", caps, err)
	}
	if err := InstallSeccomp(); err != nil {
		fail("InstallSeccomp: %v", err)
	}
	// ptrace is on the denylist. PTRACE_TRACEME (request 0) normally succeeds
	// for an unprivileged process; under our filter it must fail with EPERM.
	_, _, errno := syscall.Syscall(syscall.SYS_PTRACE, 0 /*PTRACE_TRACEME*/, 0, 0)
	if errno != syscall.EPERM {
		fail("ptrace after seccomp errno=%v (want EPERM)", errno)
	}
	fmt.Fprintln(os.Stdout, "DROP-OK")
	os.Exit(0)
}
