package auth

import (
	"encoding/base32"
	"errors"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// RFC 4226 appendix D test vectors: secret "12345678901234567890", counters 0-9.
func TestHOTPVectors(t *testing.T) {
	secret := []byte("12345678901234567890")
	want := []string{"755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"}
	for i, w := range want {
		if got := hotp(secret, uint64(i), 6); got != w {
			t.Fatalf("counter %d: got %s want %s", i, got, w)
		}
	}
}

// RFC 6238 appendix B vectors (SHA1, 8 digits) truncated to the 6-digit codes
// our implementation produces at the same instants.
func TestTOTPVectors(t *testing.T) {
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte("12345678901234567890"))
	cases := map[int64]string{
		59:          "287082", // RFC: 94287082
		1111111109:  "081804", // RFC: 07081804
		1111111111:  "050471", // RFC: 14050471
		1234567890:  "005924", // RFC: 89005924
		2000000000:  "279037", // RFC: 69279037
		20000000000: "353130", // RFC: 65353130
	}
	for ts, want := range cases {
		got, err := TOTPCode(secret, time.Unix(ts, 0))
		if err != nil || got != want {
			t.Fatalf("t=%d: got %s (%v) want %s", ts, got, err, want)
		}
		if !ValidateTOTP(secret, want, time.Unix(ts, 0)) {
			t.Fatalf("t=%d: valid code rejected", ts)
		}
		// One step of skew either way is accepted, two is not.
		if !ValidateTOTP(secret, want, time.Unix(ts+30, 0)) || !ValidateTOTP(secret, want, time.Unix(ts-30, 0)) {
			t.Fatalf("t=%d: ±1 step skew rejected", ts)
		}
		if ValidateTOTP(secret, want, time.Unix(ts+90, 0)) {
			t.Fatalf("t=%d: +3 steps accepted", ts)
		}
	}
	if ValidateTOTP(secret, "12345", time.Now()) || ValidateTOTP("not base32!", "123456", time.Now()) {
		t.Fatal("malformed input accepted")
	}
}

func newStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "users.json"))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestBootstrapCreatesAdmin(t *testing.T) {
	s := newStore(t)
	pw, err := s.Bootstrap("testudo")
	if err != nil || pw == "" {
		t.Fatalf("bootstrap: %q %v", pw, err)
	}
	u, ok := s.Get("testudo")
	if !ok || u.Role != RoleAdmin || u.Hash != "" {
		t.Fatalf("bootstrap user: %+v", u)
	}
	if again, _ := s.Bootstrap("other"); again != "" {
		t.Fatal("second bootstrap must be a no-op")
	}
	got, err := s.Authenticate("testudo", pw, "")
	if err != nil || got.Name != "testudo" {
		t.Fatalf("authenticate: %+v %v", got, err)
	}
	if _, err := s.Authenticate("testudo", "wrong", ""); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("wrong password: %v", err)
	}
	if _, err := s.Authenticate("nobody", pw, ""); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("unknown user: %v", err)
	}
}

func TestRolesAndLastAdminGuard(t *testing.T) {
	s := newStore(t)
	if _, err := s.Bootstrap("root"); err != nil {
		t.Fatal(err)
	}
	if err := s.Add("alice", "pw", RoleOperator); err != nil {
		t.Fatal(err)
	}
	if err := s.Add("alice", "pw", RoleOperator); err == nil {
		t.Fatal("duplicate add accepted")
	}
	if err := s.Add("bad name", "pw", RoleOperator); err == nil {
		t.Fatal("name with space accepted")
	}
	if err := s.Add("bob", "pw", Role("god")); err == nil {
		t.Fatal("invalid role accepted")
	}
	if err := s.SetRole("root", RoleViewer); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("demoting last admin: %v", err)
	}
	if err := s.Delete("root"); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("deleting last admin: %v", err)
	}
	if err := s.SetDisabled("root", true); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("disabling last admin: %v", err)
	}
	if err := s.SetRole("alice", RoleAdmin); err != nil {
		t.Fatal(err)
	}
	if err := s.SetRole("root", RoleViewer); err != nil {
		t.Fatalf("demote with a second admin present: %v", err)
	}
	if err := s.SetDisabled("root", true); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate("root", "x", ""); !errors.Is(err, ErrInvalidCredentials) {
		// wrong password still reads as invalid credentials, not "disabled"
		t.Fatalf("disabled + wrong pw: %v", err)
	}
	names := s.ListNames()
	if len(names) != 2 || names[0] != "alice" || names[1] != "root" {
		t.Fatalf("names = %v", names)
	}
	if !RoleAdmin.AtLeast(RoleOperator) || RoleOperator.AtLeast(RoleAdmin) || !RoleApprover.CanApprove() || RoleOperator.CanApprove() {
		t.Fatal("role ordering wrong")
	}
	// Persisted roles survive a reopen; legacy records without a role load as admin.
	s2, err := Open(s.path)
	if err != nil {
		t.Fatal(err)
	}
	if u, _ := s2.Get("alice"); u.Role != RoleAdmin {
		t.Fatalf("role not persisted: %+v", u)
	}
}

func TestTOTPEnrollmentFlow(t *testing.T) {
	s := newStore(t)
	fixed := time.Unix(1700000000, 0)
	s.now = func() time.Time { return fixed }
	if err := s.Add("alice", "pw", RoleOperator); err != nil {
		t.Fatal(err)
	}
	uri, err := s.EnrollTOTP("alice", "Testudo")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(uri, "otpauth://totp/Testudo:alice?") || !strings.Contains(uri, "secret=") {
		t.Fatalf("uri = %s", uri)
	}
	// Password alone is no longer enough.
	if _, err := s.Authenticate("alice", "pw", ""); !errors.Is(err, ErrTOTPRequired) {
		t.Fatalf("expected ErrTOTPRequired, got %v", err)
	}
	if _, err := s.Authenticate("alice", "pw", "000000"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("wrong code: %v", err)
	}
	// Recover the secret from the URI (as an authenticator app would) and
	// present a valid code.
	parsed, err := url.Parse(uri)
	if err != nil {
		t.Fatal(err)
	}
	secret := parsed.Query().Get("secret")
	if secret == "" || parsed.Query().Get("issuer") != "Testudo" {
		t.Fatalf("uri query: %s", parsed.RawQuery)
	}
	code, err := TOTPCode(secret, fixed)
	if err != nil {
		t.Fatal(err)
	}
	u, err := s.Authenticate("alice", "pw", code)
	if err != nil || u.Name != "alice" {
		t.Fatalf("authenticate with code: %v", err)
	}
	// Listings never leak the secret.
	for _, lu := range s.List() {
		if lu.Name == "alice" && (lu.TOTPSecret != "enrolled" || lu.Hash != "") {
			t.Fatalf("secret leaked in listing: %+v", lu)
		}
	}
	if err := s.DisableTOTP("alice"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate("alice", "pw", ""); err != nil {
		t.Fatalf("after disable: %v", err)
	}
	if _, err := s.EnrollTOTP("ghost", ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("enroll unknown: %v", err)
	}
}
