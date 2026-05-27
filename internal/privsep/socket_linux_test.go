//go:build linux

package privsep

import (
	"context"
	"net"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// newPair returns the two ends of a connected SOCK_SEQPACKET socketpair as
// *net.UnixConn, mirroring what Spawn sets up between engine and helper.
func newPair(t *testing.T) (client, server *net.UnixConn) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	mk := func(fd int, name string) *net.UnixConn {
		f := os.NewFile(uintptr(fd), name)
		c, err := net.FileConn(f)
		f.Close()
		if err != nil {
			t.Fatalf("fileconn: %v", err)
		}
		return c.(*net.UnixConn)
	}
	return mk(fds[0], "client"), mk(fds[1], "server")
}

func TestServeMutateRoundTrip(t *testing.T) {
	cl, sv := newPair(t)
	defer cl.Close()

	handler := func(op byte, body []byte) ([]byte, int, error) {
		if op != OpMutate {
			t.Errorf("unexpected op %#x", op)
		}
		return append([]byte("echo:"), body...), -1, nil
	}
	srv := NewServer(sv, handler)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Serve(ctx) }()

	client := NewClient(cl)
	resp, fd, err := client.Call(OpMutate, []byte("hello"))
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	if fd != -1 {
		t.Fatalf("unexpected fd %d", fd)
	}
	if string(resp) != "echo:hello" {
		t.Fatalf("resp = %q", resp)
	}
}

func TestServeErrorResponse(t *testing.T) {
	cl, sv := newPair(t)
	defer cl.Close()
	srv := NewServer(sv, func(byte, []byte) ([]byte, int, error) {
		return nil, -1, os.ErrPermission
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Serve(ctx) }()

	_, _, err := NewClient(cl).Call(OpMutate, nil)
	if err == nil {
		t.Fatal("expected error response")
	}
	if err.Error() != os.ErrPermission.Error() {
		t.Fatalf("err = %q", err.Error())
	}
}

// TestFDPassing exercises a real SCM_RIGHTS round trip: the handler opens a
// pipe and returns the read end; the client must receive a usable fd and read
// the byte the test writes into the write end.
func TestFDPassing(t *testing.T) {
	cl, sv := newPair(t)
	defer cl.Close()

	var pipeR, pipeW int
	fds := make([]int, 2)
	if err := unix.Pipe(fds); err != nil {
		t.Fatalf("pipe: %v", err)
	}
	pipeR, pipeW = fds[0], fds[1]
	defer unix.Close(pipeW)

	srv := NewServer(sv, func(byte, []byte) ([]byte, int, error) {
		return []byte("here"), pipeR, nil // transfers ownership of pipeR
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Serve(ctx) }()

	resp, fd, err := NewClient(cl).Call(OpOpenSocket, nil)
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	if string(resp) != "here" {
		t.Fatalf("resp = %q", resp)
	}
	if fd < 0 {
		t.Fatal("expected an fd via SCM_RIGHTS")
	}
	defer unix.Close(fd)

	if _, err := unix.Write(pipeW, []byte("X")); err != nil {
		t.Fatalf("write to passed pipe: %v", err)
	}
	buf := make([]byte, 1)
	if _, err := unix.Read(fd, buf); err != nil {
		t.Fatalf("read from received fd: %v", err)
	}
	if buf[0] != 'X' {
		t.Fatalf("received byte = %q via passed fd", buf[0])
	}
}

func TestPeerUID(t *testing.T) {
	cl, sv := newPair(t)
	defer cl.Close()
	defer sv.Close()
	uid, err := PeerUID(sv)
	if err != nil {
		t.Fatalf("PeerUID: %v", err)
	}
	if uid != uint32(os.Getuid()) {
		t.Fatalf("peer uid = %d, want %d", uid, os.Getuid())
	}
}

// TestPeerRejection verifies the SO_PEERCRED gate refuses a peer whose uid does
// not match the allowed uid. Both ends share this process's uid, so we set the
// allowed uid to a value we definitely are not.
func TestPeerRejection(t *testing.T) {
	cl, sv := newPair(t)
	defer cl.Close()

	srv := NewServer(sv, func(byte, []byte) ([]byte, int, error) {
		t.Error("handler must not run for a rejected peer")
		return nil, -1, nil
	})
	srv.RestrictPeer(uint32(os.Getuid()) + 1) // never us
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx) }()

	_, _, err := NewClient(cl).Call(OpMutate, []byte("should be rejected"))
	if err == nil {
		t.Fatal("expected rejection error to client")
	}
	select {
	case serveErr := <-done:
		if serveErr == nil {
			t.Fatal("Serve should return a rejection error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not return after rejecting peer")
	}
}
