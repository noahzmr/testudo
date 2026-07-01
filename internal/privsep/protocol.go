// Package privsep implements Testudo's privilege-separation transport: a thin
// privileged helper process holds CAP_NET_RAW / CAP_NET_ADMIN and performs the
// narrow set of operations that need them, while the main engine (web server,
// TUI, collectors, analyzers) runs unprivileged and talks to the helper over a
// local SOCK_SEQPACKET socket.
//
// The wire protocol is deliberately tiny: each request and response is a single
// SEQPACKET datagram framed as an opcode/status byte followed by an opaque
// body. Bodies are produced and consumed by callers (e.g. the netops package
// encodes its mutation descriptor into the body); privsep itself stays
// op-agnostic so it never imports netops, avoiding an import cycle and keeping
// the transport independently testable.
//
// File descriptors (raw sockets opened by the helper) travel out-of-band in the
// response via SCM_RIGHTS. SO_PEERCRED on the helper side authenticates the
// connecting process.
package privsep

import "errors"

// Opcodes name the privileged operations the helper exposes. Bodies are opaque
// to privsep - the caller and handler agree on their encoding.
const (
	OpPing       byte = 0x01 // liveness handshake; empty body
	OpMutate     byte = 0x02 // body = encoded netops mutation descriptor
	OpOpenSocket byte = 0x03 // body = encoded socket request; response carries an fd via SCM_RIGHTS

	// Capture opcodes let the unprivileged engine drive a tcpdump child that the
	// privileged helper owns. The helper holds CAP_NET_RAW; a child it execs
	// inherits it via the uid-0 root-exception, which the capability-stripped
	// engine cannot do for its own children.
	OpCaptureStart  byte = 0x04 // body = JSON {args:[]string}; resp = JSON {pid:int}
	OpCaptureStop   byte = 0x05 // body = JSON {pid:int}; signals the process group
	OpCaptureStatus byte = 0x06 // body = JSON {pid:int}; resp = JSON {state,exitErr,done}

	// OpQuery performs a privileged READ and returns its result in the response
	// body. Unlike OpMutate (error only), the body carries JSON. Used for reads
	// that need capabilities/root, e.g. listing /etc/netplan (0600 files).
	OpQuery byte = 0x07 // body = encoded netops query descriptor; resp = JSON
)

// Response status bytes.
const (
	StatusOK  byte = 0x00
	StatusErr byte = 0x01 // body is a UTF-8 error message
)

// MaxFrame bounds a single datagram so a malformed length can't make either
// side allocate without limit. SEQPACKET messages are small (a JSON mutation
// descriptor or an error string), so 64 KiB is generous.
const MaxFrame = 64 << 10

var (
	errEmptyFrame  = errors.New("privsep: empty frame")
	errFrameTooBig = errors.New("privsep: frame exceeds MaxFrame")
)

// EncodeRequest frames an opcode + body into a single datagram payload.
func EncodeRequest(op byte, body []byte) []byte {
	out := make([]byte, 1+len(body))
	out[0] = op
	copy(out[1:], body)
	return out
}

// DecodeRequest splits a request datagram into its opcode and body. The body
// aliases frame's backing array; callers that retain it should copy.
func DecodeRequest(frame []byte) (op byte, body []byte, err error) {
	if len(frame) == 0 {
		return 0, nil, errEmptyFrame
	}
	if len(frame) > MaxFrame {
		return 0, nil, errFrameTooBig
	}
	return frame[0], frame[1:], nil
}

// EncodeResponse frames a status byte + body into a single datagram payload.
func EncodeResponse(status byte, body []byte) []byte {
	out := make([]byte, 1+len(body))
	out[0] = status
	copy(out[1:], body)
	return out
}

// DecodeResponse splits a response datagram into its status and body.
func DecodeResponse(frame []byte) (status byte, body []byte, err error) {
	if len(frame) == 0 {
		return 0, nil, errEmptyFrame
	}
	if len(frame) > MaxFrame {
		return 0, nil, errFrameTooBig
	}
	return frame[0], frame[1:], nil
}

// errorBody renders an error for the wire. A nil error encodes empty.
func errorBody(err error) []byte {
	if err == nil {
		return nil
	}
	return []byte(err.Error())
}
