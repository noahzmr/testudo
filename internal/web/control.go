package web

import (
	"context"
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"golang.org/x/sys/unix"

	"github.com/noahzmr/testudo/internal/identity"
)

// The control socket lets the host's administrator (root, or the user the
// daemon runs as) drive the API from the command line: `testudo user
// passwd` and the like. It is a UNIX socket in the storage directory with
// mode 0600; the peer's user id is checked on every connection. A request
// over it acts as the host's break-glass administrator, which is no more
// than root on the host can do anyway, and is audited under that name.

type controlKey struct{}

// ControlActor names requests made over the control socket in audit rows.
const ControlActor = "host-root"

func controlPeerAllowed(c net.Conn) bool {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return false
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return false
	}
	var cred *unix.Ucred
	var cerr error
	if err := raw.Control(func(fd uintptr) { cred, cerr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) }); err != nil || cerr != nil {
		return false
	}
	return cred.Uid == 0 || int(cred.Uid) == os.Getuid()
}

// controlSession is the session of a request that came over the control
// socket, or nil.
func controlSession(r *http.Request) *sessionRecord {
	if ok, _ := r.Context().Value(controlKey{}).(bool); !ok {
		return nil
	}
	p := identity.Principal{Name: ControlActor, Source: identity.SourcePAM, Permissions: identity.BuiltinRoles[identity.RoleAdmin], BreakGlass: true}
	return &sessionRecord{user: p.Name, role: p.LegacyRole(), principal: p, expiresAt: time.Now().Add(time.Minute)}
}

// serveControl serves the API on the control socket until ctx ends.
func (s *Server) serveControl(ctx context.Context, path string) {
	_ = os.Remove(path)
	ln, err := net.Listen("unix", path)
	if err != nil {
		log.Printf("web: control socket: %v", err)
		return
	}
	if err := os.Chmod(path, 0o600); err != nil {
		ln.Close()
		log.Printf("web: control socket: %v", err)
		return
	}
	srv := &http.Server{Handler: s.mux, ReadHeaderTimeout: 5 * time.Second,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return context.WithValue(ctx, controlKey{}, controlPeerAllowed(c))
		}}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
		_ = os.Remove(path)
	}()
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Printf("web: control socket: %v", err)
	}
}
