//go:build linux

// Package testnet builds throwaway network topologies for integration tests:
// network namespaces joined by veth pairs, all inside a private namespace so
// nothing a test does can reach the host's interfaces, routes or ruleset.
//
// It is the kernel-level equivalent of `ip netns add` + `ip link add ... type
// veth`, done through netlink and setns(2) directly. That keeps the test
// binary self-contained: it needs neither iproute2 nor a writable /run/netns,
// so the same binary runs unprivileged in a user namespace, as root, or
// statically linked inside a minimal container.
//
// Usage:
//
//	func TestSomething(t *testing.T) {
//		if testnet.Isolate(t) {
//			return // the test body ran in the re-executed child
//		}
//		client := testnet.NewNS(t, "client")
//		testnet.Veth(t, "lan0", client, "eth0")
//		...
//	}
package testnet

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	// insideEnv marks the re-executed test process that already runs inside
	// its private network namespace.
	insideEnv = "TESTUDO_TESTNET_INSIDE"
	// RequireEnv turns "namespaces unavailable" from a skip into a failure.
	// CI sets it so a missing capability can never hide a regression.
	RequireEnv = "TESTUDO_REQUIRE_NETNS"

	unavailableMarker = "TESTNET-UNAVAILABLE:"
)

// Isolate re-executes the calling top-level test inside a fresh network
// namespace. It returns true in the parent once the child has passed (the
// caller must return immediately) and false in the child (the caller runs the
// test body).
//
// As root the child gets a new network namespace only. Otherwise it also gets
// a user namespace in which the caller is mapped to uid 0, which grants
// CAP_NET_ADMIN and CAP_NET_RAW over the private network namespace. Hosts that
// forbid this (hardened kernels, AppArmor-restricted user namespaces, most
// containers) make the test skip, or fail when TESTUDO_REQUIRE_NETNS=1.
func Isolate(t *testing.T) bool {
	t.Helper()
	if os.Getenv(insideEnv) != "" {
		if err := preflight(); err != nil {
			// Reported on stdout so the parent can tell "cannot run here"
			// apart from a genuine failure.
			fmt.Printf("%s %v\n", unavailableMarker, err)
			os.Exit(0)
		}
		return false
	}
	if testing.Short() {
		t.Skip("namespace integration test skipped in -short mode")
	}
	exe, err := os.Executable()
	if err != nil {
		unavailable(t, fmt.Sprintf("cannot locate test binary: %v", err))
	}
	cmd := exec.Command(exe, "-test.run", "^"+t.Name()+"$", "-test.v", "-test.count=1")
	cmd.Env = append(os.Environ(), insideEnv+"=1")
	attr := &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWNET}
	if os.Geteuid() != 0 {
		attr.Cloneflags |= syscall.CLONE_NEWUSER
		attr.UidMappings = []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}}
		attr.GidMappings = []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}}
	}
	cmd.SysProcAttr = attr
	out, err := cmd.CombinedOutput()
	s := string(out)
	if i := strings.Index(s, unavailableMarker); i >= 0 {
		unavailable(t, strings.TrimSpace(strings.SplitN(s[i+len(unavailableMarker):], "\n", 2)[0]))
	}
	if err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			// The clone itself was refused: the child never ran.
			unavailable(t, err.Error())
		}
		t.Fatalf("namespaced test failed: %v\n%s", err, s)
	}
	if !strings.Contains(s, "--- PASS: "+t.Name()) {
		t.Fatalf("namespaced test did not report PASS:\n%s", s)
	}
	return true
}

func unavailable(t *testing.T, why string) {
	t.Helper()
	msg := "private network namespace unavailable: " + why
	if os.Getenv(RequireEnv) != "" {
		t.Fatalf("%s (%s is set)", msg, RequireEnv)
	}
	t.Skip(msg)
}

// preflight proves the process really holds CAP_NET_ADMIN over its network
// namespace by creating and deleting a dummy link, and brings loopback up.
func preflight() error {
	probe := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "tnprobe0"}}
	if err := netlink.LinkAdd(probe); err != nil {
		return fmt.Errorf("no CAP_NET_ADMIN in namespace: %w", err)
	}
	if err := netlink.LinkDel(probe); err != nil {
		return err
	}
	lo, err := netlink.LinkByName("lo")
	if err != nil {
		return err
	}
	return netlink.LinkSetUp(lo)
}

// NS is a network namespace owned by the test. The namespace the test process
// itself runs in (after Isolate) is the "root" of the topology; every NS is a
// further namespace hanging off it.
type NS struct {
	Name string
	fd   int
}

// NewNS creates an empty network namespace with loopback up. It is destroyed
// when the test ends.
func NewNS(t *testing.T, name string) *NS {
	t.Helper()
	ns := &NS{Name: name, fd: -1}
	err := onLockedThread(func() error {
		if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
			return fmt.Errorf("unshare netns: %w", err)
		}
		fd, err := unix.Open("/proc/thread-self/ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			return fmt.Errorf("open new netns: %w", err)
		}
		ns.fd = fd
		lo, err := netlink.LinkByName("lo")
		if err != nil {
			return err
		}
		return netlink.LinkSetUp(lo)
	})
	if err != nil {
		t.Fatalf("testnet: create namespace %q: %v", name, err)
	}
	t.Cleanup(func() { _ = unix.Close(ns.fd) })
	return ns
}

// Do runs fn with the calling goroutine's OS thread switched into the
// namespace. Sockets and netlink handles created inside fn stay bound to the
// namespace after Do returns, so a listener opened here can be served from
// ordinary goroutines. fn must not start goroutines that are expected to run
// inside the namespace.
func (ns *NS) Do(fn func() error) error {
	return onLockedThread(func() error {
		if err := unix.Setns(ns.fd, unix.CLONE_NEWNET); err != nil {
			return fmt.Errorf("setns %s: %w", ns.Name, err)
		}
		return fn()
	})
}

// onLockedThread runs fn on a dedicated OS thread and restores that thread's
// original network namespace afterwards. If the restore fails the thread is
// left locked, so the runtime discards it instead of reusing a thread that
// sits in the wrong namespace.
func onLockedThread(fn func() error) error {
	errc := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		orig, err := unix.Open("/proc/thread-self/ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			errc <- fmt.Errorf("open current netns: %w", err)
			return
		}
		defer unix.Close(orig)
		ferr := fn()
		if err := unix.Setns(orig, unix.CLONE_NEWNET); err != nil {
			errc <- errors.Join(ferr, fmt.Errorf("restore netns: %w", err))
			return // stay locked: thread dies with the goroutine
		}
		runtime.UnlockOSThread()
		errc <- ferr
	}()
	return <-errc
}

// Veth creates a veth pair: rootName in the test's root namespace and
// peerName inside peer. Both ends are brought up.
func Veth(t *testing.T, rootName string, peer *NS, peerName string) {
	t.Helper()
	v := &netlink.Veth{
		LinkAttrs:     netlink.LinkAttrs{Name: rootName},
		PeerName:      peerName,
		PeerNamespace: netlink.NsFd(peer.fd),
	}
	if err := netlink.LinkAdd(v); err != nil {
		t.Fatalf("testnet: veth %s<->%s@%s: %v", rootName, peerName, peer.Name, err)
	}
	if err := linkUp(rootName); err != nil {
		t.Fatalf("testnet: up %s: %v", rootName, err)
	}
	if err := peer.Do(func() error { return linkUp(peerName) }); err != nil {
		t.Fatalf("testnet: up %s@%s: %v", peerName, peer.Name, err)
	}
}

func linkUp(name string) error {
	l, err := netlink.LinkByName(name)
	if err != nil {
		return err
	}
	return netlink.LinkSetUp(l)
}

// Addr assigns a CIDR address (IPv4 or IPv6) to a link in the current
// namespace. IPv6 addresses skip duplicate address detection so they are
// usable immediately. Call it inside NS.Do to address a peer namespace.
func Addr(link, cidr string) error {
	l, err := netlink.LinkByName(link)
	if err != nil {
		return err
	}
	a, err := netlink.ParseAddr(cidr)
	if err != nil {
		return err
	}
	if a.IP.To4() == nil {
		a.Flags |= unix.IFA_F_NODAD
	}
	return netlink.AddrAdd(l, a)
}

// DefaultRoute installs a default route via gw in the current namespace.
func DefaultRoute(gw string) error {
	ip := net.ParseIP(gw)
	if ip == nil {
		return fmt.Errorf("bad gateway %q", gw)
	}
	dst := &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)}
	if ip.To4() == nil {
		dst = &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)}
	}
	return netlink.RouteAdd(&netlink.Route{Dst: dst, Gw: ip})
}

// Sysctl writes a value below /proc/sys for the current namespace, e.g.
// Sysctl("net/ipv4/ip_forward", "1").
func Sysctl(key, value string) error {
	return os.WriteFile("/proc/sys/"+key, []byte(value), 0o644)
}

// Must fails the test when err is non-nil; it keeps topology setup readable.
func Must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("testnet: %v", err)
	}
}
