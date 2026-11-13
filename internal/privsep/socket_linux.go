//go:build linux

package privsep

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"

	"golang.org/x/sys/unix"
)

// Client is the engine-side handle to the privileged helper. It is safe for
// concurrent use: each Call holds the connection lock for one request/response
// round-trip, which is fine for the low-frequency mutation traffic.
type Client struct {
	mu   sync.Mutex
	conn *net.UnixConn
}

// NewClient wraps an established SEQPACKET connection to the helper.
func NewClient(conn *net.UnixConn) *Client { return &Client{conn: conn} }

// Call sends one request and waits for the response. A returned fd (>= 0) is a
// real file descriptor passed back via SCM_RIGHTS and owned by the caller, who
// must close it. fd is -1 when the response carries none.
func (c *Client) Call(op byte, body []byte) (resp []byte, fd int, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn == nil {
		return nil, -1, errors.New("privsep: client closed")
	}
	if len(body) > MaxMessage {
		return nil, -1, errMessageTooBig
	}
	// A body larger than one datagram goes out as OpContinue chunks followed
	// by the real opcode on the last chunk; the server reassembles in order.
	parts := chunks(body)
	for i, part := range parts {
		frameOp := OpContinue
		if i == len(parts)-1 {
			frameOp = op
		}
		if _, _, werr := c.conn.WriteMsgUnix(EncodeRequest(frameOp, part), nil, nil); werr != nil {
			return nil, -1, fmt.Errorf("privsep: write: %w", werr)
		}
	}

	// Read the response: zero or more StatusMore chunks, then the final frame.
	// Only the final frame may carry an fd.
	buf := make([]byte, MaxFrame)
	oob := make([]byte, unix.CmsgSpace(4)) // room for one fd
	var out []byte
	for {
		n, oobn, _, _, rerr := c.conn.ReadMsgUnix(buf, oob)
		if rerr != nil {
			return nil, -1, fmt.Errorf("privsep: read: %w", rerr)
		}
		gotFD := parseSingleFD(oob[:oobn])
		status, rbody, derr := DecodeResponse(buf[:n])
		if derr != nil {
			closeFD(gotFD)
			return nil, -1, derr
		}
		if len(out)+len(rbody) > MaxMessage {
			closeFD(gotFD)
			return nil, -1, errMessageTooBig
		}
		out = append(out, rbody...)
		switch status {
		case StatusMore:
			closeFD(gotFD) // never expected on a continuation; don't leak it
			continue
		case StatusErr:
			closeFD(gotFD)
			return nil, -1, errors.New(string(out))
		default:
			return out, gotFD, nil
		}
	}
}

// Ping verifies the helper is alive and responding.
func (c *Client) Ping() error {
	_, fd, err := c.Call(OpPing, nil)
	closeFD(fd)
	return err
}

// Close shuts the connection to the helper.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn == nil {
		return nil
	}
	err := c.conn.Close()
	c.conn = nil
	return err
}

// Handler executes one privileged request. It returns the response body and,
// optionally, a file descriptor to hand back to the caller (>= 0). The helper
// retains ownership only until it is sent; returning fd >= 0 transfers it.
type Handler func(op byte, body []byte) (resp []byte, fd int, err error)

// AuditFunc is called once per handled request with the peer's uid and the
// result, so the helper can append to the audit log.
type AuditFunc func(op byte, body []byte, peerUID uint32, err error)

// Server is the helper-side request loop bound to one SEQPACKET connection.
type Server struct {
	conn       *net.UnixConn
	handler    Handler
	audit      AuditFunc
	allowedUID uint32
	enforceUID bool
}

// NewServer binds a handler to a connection. When enforceUID is true, requests
// from a peer whose SO_PEERCRED uid differs from allowedUID are rejected.
func NewServer(conn *net.UnixConn, h Handler) *Server {
	return &Server{conn: conn, handler: h}
}

// SetAudit installs an audit callback invoked after each handled request.
func (s *Server) SetAudit(fn AuditFunc) { s.audit = fn }

// RestrictPeer enables SO_PEERCRED enforcement: only a peer running as uid is
// served; anything else is refused with an error response.
func (s *Server) RestrictPeer(uid uint32) {
	s.allowedUID = uid
	s.enforceUID = true
}

// Serve reads requests until ctx is cancelled or the peer disconnects.
func (s *Server) Serve(ctx context.Context) error {
	go func() {
		<-ctx.Done()
		_ = s.conn.Close()
	}()

	peerUID, peerErr := PeerUID(s.conn)
	if peerErr == nil && s.enforceUID && peerUID != s.allowedUID {
		// Refuse to serve a mis-credentialed peer at all.
		_ = s.writeErr(fmt.Errorf("privsep: peer uid %d not authorised", peerUID))
		return fmt.Errorf("privsep: rejected peer uid %d (want %d)", peerUID, s.allowedUID)
	}

	buf := make([]byte, MaxFrame)
	var pending []byte // reassembly buffer for OpContinue chunks
	for {
		n, _, _, _, err := s.conn.ReadMsgUnix(buf, nil)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("privsep: serve read: %w", err)
		}
		op, body, derr := DecodeRequest(buf[:n])
		if derr != nil {
			pending = nil
			_ = s.writeErr(derr)
			continue
		}
		if len(pending)+len(body) > MaxMessage {
			pending = nil
			_ = s.writeErr(errMessageTooBig)
			continue
		}
		if op == OpContinue {
			pending = append(pending, body...)
			continue
		}
		if pending != nil {
			body = append(pending, body...)
			pending = nil
		}
		s.dispatch(op, body, peerUID)
	}
}

func (s *Server) dispatch(op byte, body []byte, peerUID uint32) {
	if op == OpPing {
		_ = s.writeOK(nil, -1)
		if s.audit != nil {
			s.audit(op, body, peerUID, nil)
		}
		return
	}
	resp, fd, herr := s.handler(op, body)
	if s.audit != nil {
		s.audit(op, body, peerUID, herr)
	}
	if herr != nil {
		closeFD(fd)
		_ = s.writeErr(herr)
		return
	}
	if werr := s.writeOK(resp, fd); werr != nil {
		closeFD(fd)
		return
	}
	// The fd has been duplicated into the peer by the kernel; close our copy.
	closeFD(fd)
}

// writeOK sends a response, split into StatusMore chunks when it exceeds one
// datagram. The fd, if any, rides on the final frame.
func (s *Server) writeOK(body []byte, fd int) error {
	if len(body) > MaxMessage {
		return s.writeErr(errMessageTooBig)
	}
	parts := chunks(body)
	for i, part := range parts {
		status := StatusMore
		var oob []byte
		if i == len(parts)-1 {
			status = StatusOK
			if fd >= 0 {
				oob = unix.UnixRights(fd)
			}
		}
		if _, _, err := s.conn.WriteMsgUnix(EncodeResponse(status, part), oob, nil); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) writeErr(e error) error {
	msg := errorBody(e)
	if len(msg) > chunkSize {
		msg = msg[:chunkSize]
	}
	frame := EncodeResponse(StatusErr, msg)
	_, _, err := s.conn.WriteMsgUnix(frame, nil, nil)
	return err
}

// PeerUID returns the uid of the process on the far end of conn via SO_PEERCRED.
func PeerUID(conn *net.UnixConn) (uint32, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var ucred *unix.Ucred
	var serr error
	cerr := raw.Control(func(fd uintptr) {
		ucred, serr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	})
	if cerr != nil {
		return 0, cerr
	}
	if serr != nil {
		return 0, serr
	}
	return ucred.Uid, nil
}

// parseSingleFD extracts the first fd from an SCM_RIGHTS control message, or -1.
func parseSingleFD(oob []byte) int {
	if len(oob) == 0 {
		return -1
	}
	msgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return -1
	}
	for _, m := range msgs {
		fds, err := unix.ParseUnixRights(&m)
		if err != nil || len(fds) == 0 {
			continue
		}
		// Close any extras; we only expect one.
		for _, extra := range fds[1:] {
			closeFD(extra)
		}
		return fds[0]
	}
	return -1
}

func closeFD(fd int) {
	if fd >= 0 {
		_ = unix.Close(fd)
	}
}
