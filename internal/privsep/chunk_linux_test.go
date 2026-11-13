//go:build linux

package privsep

import (
	"bytes"
	"errors"
	"testing"
)

// TestLargeRequestAndResponseAreChunked sends a request body and receives a
// response body that each span several datagrams, and checks both arrive
// intact and in order.
func TestLargeRequestAndResponseAreChunked(t *testing.T) {
	cl, sv := newPair(t)
	defer cl.Close()

	// 3.5 frames of request, 5.2 frames of response; patterned so a
	// reordered or dropped chunk would be detected.
	req := pattern(MaxFrame * 35 / 10)
	resp := pattern(MaxFrame * 52 / 10)
	var gotReq []byte
	handler := func(op byte, body []byte) ([]byte, int, error) {
		if op != OpQuery {
			t.Errorf("op = %#x, want OpQuery", op)
		}
		gotReq = append([]byte(nil), body...)
		return resp, -1, nil
	}
	srv := NewServer(sv, handler)
	go func() { _ = srv.Serve(t.Context()) }()

	client := NewClient(cl)
	got, fd, err := client.Call(OpQuery, req)
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	if fd != -1 {
		t.Fatalf("unexpected fd %d", fd)
	}
	if !bytes.Equal(gotReq, req) {
		t.Fatalf("request body corrupted: got %d bytes, want %d", len(gotReq), len(req))
	}
	if !bytes.Equal(got, resp) {
		t.Fatalf("response body corrupted: got %d bytes, want %d", len(got), len(resp))
	}

	// A second, small call on the same connection still works (no leftover
	// reassembly state on either side).
	got, _, err = client.Call(OpQuery, []byte("small"))
	if err != nil || !bytes.Equal(gotReq, []byte("small")) || !bytes.Equal(got, resp) {
		t.Fatalf("follow-up call: err=%v req=%q", err, gotReq)
	}
}

// TestErrorAfterLargeRequest checks an error response to a chunked request is
// delivered as an error (not as a truncated body).
func TestErrorAfterLargeRequest(t *testing.T) {
	cl, sv := newPair(t)
	defer cl.Close()
	srv := NewServer(sv, func(op byte, body []byte) ([]byte, int, error) {
		return nil, -1, errors.New("nope: " + string(body[:4]))
	})
	go func() { _ = srv.Serve(t.Context()) }()

	_, _, err := NewClient(cl).Call(OpMutate, append([]byte("abcd"), pattern(2*MaxFrame)...))
	if err == nil || err.Error() != "nope: abcd" {
		t.Fatalf("err = %v", err)
	}
}

func TestMessageCapRefused(t *testing.T) {
	cl, sv := newPair(t)
	defer cl.Close()
	srv := NewServer(sv, func(byte, []byte) ([]byte, int, error) { return nil, -1, nil })
	go func() { _ = srv.Serve(t.Context()) }()

	if _, _, err := NewClient(cl).Call(OpQuery, make([]byte, MaxMessage+1)); !errors.Is(err, errMessageTooBig) {
		t.Fatalf("oversize request: %v", err)
	}
}

func TestChunksSplit(t *testing.T) {
	if c := chunks(nil); len(c) != 1 || len(c[0]) != 0 {
		t.Fatalf("empty body chunks = %v", c)
	}
	if c := chunks(make([]byte, chunkSize)); len(c) != 1 {
		t.Fatalf("exactly one chunk expected, got %d", len(c))
	}
	c := chunks(make([]byte, chunkSize+1))
	if len(c) != 2 || len(c[0]) != chunkSize || len(c[1]) != 1 {
		t.Fatalf("chunks = %d/%d", len(c[0]), len(c[1]))
	}
}

// pattern returns n bytes with a position-dependent value.
func pattern(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*7 + i>>8)
	}
	return b
}
