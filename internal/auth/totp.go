package auth

import (
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // RFC 6238 default algorithm; what authenticator apps expect
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

// TOTP per RFC 6238 (HMAC-SHA1, 30-second step, 6 digits) implemented
// in-process so MFA needs no new dependency. One step of clock skew is
// accepted in each direction, which is what every authenticator app assumes.
const (
	totpStep   = 30 * time.Second
	totpDigits = 6
	totpSkew   = 1
)

// hotp computes RFC 4226 HOTP for a counter.
func hotp(secret []byte, counter uint64, digits int) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	mac := hmac.New(sha1.New, secret)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	code := (uint32(sum[offset])&0x7f)<<24 |
		uint32(sum[offset+1])<<16 |
		uint32(sum[offset+2])<<8 |
		uint32(sum[offset+3])
	mod := uint32(1)
	for range digits {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, code%mod)
}

// TOTPCode returns the code for a base32 secret at time t.
func TOTPCode(secretB32 string, t time.Time) (string, error) {
	secret, err := decodeSecret(secretB32)
	if err != nil {
		return "", err
	}
	return hotp(secret, uint64(t.Unix())/uint64(totpStep.Seconds()), totpDigits), nil
}

// ValidateTOTP reports whether code is valid for the secret at time t,
// accepting ±totpSkew steps. Constant-time compare per candidate.
func ValidateTOTP(secretB32, code string, t time.Time) bool {
	secret, err := decodeSecret(secretB32)
	if err != nil || len(code) != totpDigits {
		return false
	}
	counter := int64(t.Unix()) / int64(totpStep.Seconds())
	ok := false
	for d := -int64(totpSkew); d <= int64(totpSkew); d++ {
		want := hotp(secret, uint64(counter+d), totpDigits)
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			ok = true // keep looping: constant work regardless of which step matched
		}
	}
	return ok
}

func decodeSecret(s string) ([]byte, error) {
	s = strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(s), " ", ""))
	s = strings.TrimRight(s, "=")
	return base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(s)
}
