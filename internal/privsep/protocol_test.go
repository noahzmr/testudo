package privsep

import (
	"bytes"
	"errors"
	"testing"
)

func TestRequestRoundTrip(t *testing.T) {
	cases := []struct {
		name string
		op   byte
		body []byte
	}{
		{"ping-empty", OpPing, nil},
		{"mutate", OpMutate, []byte(`{"kind":"add_route"}`)},
		{"opensocket", OpOpenSocket, []byte("eth0")},
		{"binary-body", OpMutate, []byte{0x00, 0xff, 0x10, 0x00}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			frame := EncodeRequest(tc.op, tc.body)
			op, body, err := DecodeRequest(frame)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if op != tc.op {
				t.Fatalf("op = %#x, want %#x", op, tc.op)
			}
			if !bytes.Equal(body, tc.body) && !(len(body) == 0 && len(tc.body) == 0) {
				t.Fatalf("body = %v, want %v", body, tc.body)
			}
		})
	}
}

func TestResponseRoundTrip(t *testing.T) {
	okFrame := EncodeResponse(StatusOK, []byte("result"))
	st, body, err := DecodeResponse(okFrame)
	if err != nil {
		t.Fatal(err)
	}
	if st != StatusOK || string(body) != "result" {
		t.Fatalf("ok decode: st=%#x body=%q", st, body)
	}

	errFrame := EncodeResponse(StatusErr, errorBody(errors.New("permission denied")))
	st, body, err = DecodeResponse(errFrame)
	if err != nil {
		t.Fatal(err)
	}
	if st != StatusErr || string(body) != "permission denied" {
		t.Fatalf("err decode: st=%#x body=%q", st, body)
	}
}

func TestDecodeEmptyFrame(t *testing.T) {
	if _, _, err := DecodeRequest(nil); err == nil {
		t.Fatal("empty request frame should error")
	}
	if _, _, err := DecodeResponse([]byte{}); err == nil {
		t.Fatal("empty response frame should error")
	}
}

func TestDecodeOversizeFrame(t *testing.T) {
	big := make([]byte, MaxFrame+1)
	if _, _, err := DecodeRequest(big); !errors.Is(err, errFrameTooBig) {
		t.Fatalf("oversize request err = %v", err)
	}
}

func TestErrorBodyNil(t *testing.T) {
	if b := errorBody(nil); b != nil {
		t.Fatalf("errorBody(nil) = %v, want nil", b)
	}
}
