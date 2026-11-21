//go:build linux

package nflog

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// Open creates a netlink socket bound to the log group and returns its
// descriptor. It needs CAP_NET_ADMIN.
func Open(group uint16) (int, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, netlinkNetfilter)
	if err != nil {
		return -1, fmt.Errorf("nflog: socket: %w", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		unix.Close(fd)
		return -1, fmt.Errorf("nflog: bind: %w", err)
	}
	// A busy log must not block the kernel; drop rather than wait.
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, 4<<20)
	buf := make([]byte, 4096)
	for _, m := range bindMessages(group) {
		if err := unix.Sendto(fd, m, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
			unix.Close(fd)
			return -1, fmt.Errorf("nflog: configure: %w", err)
		}
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			unix.Close(fd)
			return -1, fmt.Errorf("nflog: configure: %w", err)
		}
		if err := ackError(buf[:n]); err != nil {
			unix.Close(fd)
			return -1, err
		}
	}
	return fd, nil
}

// Reader reads logged packets from an open socket. It needs no privileges.
type Reader struct {
	f   *os.File
	buf []byte
}

// NewReader takes over the descriptor. It is read through Go's poller, so
// Close ends a Read that waits.
func NewReader(fd int) *Reader {
	_ = unix.SetNonblock(fd, true)
	return &Reader{f: os.NewFile(uintptr(fd), "nflog"), buf: make([]byte, 1<<16)}
}

// Read blocks until the kernel sends packets and returns them. A full
// socket buffer (ENOBUFS) loses packets but not the reader.
func (r *Reader) Read() ([]Entry, error) {
	for {
		n, err := r.f.Read(r.buf)
		if errors.Is(err, unix.ENOBUFS) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if evs := Parse(r.buf[:n]); len(evs) > 0 {
			return evs, nil
		}
	}
}

// Close closes the socket and ends a Read.
func (r *Reader) Close() error { return r.f.Close() }
