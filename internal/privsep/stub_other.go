//go:build !linux

package privsep

import (
	"context"
	"errors"
	"os/exec"
)

// errUnsupported is returned by every privilege-separation entry point on
// non-Linux platforms. Testudo targets Linux; these stubs exist only so the
// tree compiles for tooling on other OSes.
var errUnsupported = errors.New("privsep: only supported on Linux")

// Client is a non-functional placeholder on non-Linux platforms.
type Client struct{}

func (c *Client) Call(byte, []byte) ([]byte, int, error) { return nil, -1, errUnsupported }
func (c *Client) Ping() error                            { return errUnsupported }
func (c *Client) Close() error                           { return nil }

// Handler matches the Linux signature so callers compile everywhere.
type Handler func(op byte, body []byte) (resp []byte, fd int, err error)

// AuditFunc matches the Linux signature.
type AuditFunc func(op byte, body []byte, peerUID uint32, err error)

func Spawn(context.Context) (*Client, *exec.Cmd, error) { return nil, nil, errUnsupported }
func RunHelper(Handler, AuditFunc) error                { return errUnsupported }
func DropPrivileges() error                             { return errUnsupported }
func InstallSeccomp() error                             { return errUnsupported }
func NoNewPrivs() (bool, error)                         { return false, errUnsupported }
func EffectiveCaps() (uint64, error)                    { return 0, errUnsupported }
