package sshca

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func userKey(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return string(ssh.MarshalAuthorizedKey(sshPub))
}

func TestOpenGeneratesAndReloads(t *testing.T) {
	dir := t.TempDir()
	ca, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(filepath.Join(dir, "ca"))
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("ca key perms: %v %v", st, err)
	}
	pub1 := ca.PublicKey()
	if !strings.HasPrefix(pub1, "ssh-ed25519 ") {
		t.Fatalf("public key = %q", pub1)
	}
	ca2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if ca2.PublicKey() != pub1 || ca2.Fingerprint() != ca.Fingerprint() {
		t.Fatal("reopen must load the same key")
	}
	if _, err := Open(""); err == nil {
		t.Fatal("empty dir accepted")
	}
}

func TestSignProducesValidUserCert(t *testing.T) {
	ca, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	fixed := time.Unix(1700000000, 0)
	ca.now = func() time.Time { return fixed }
	start, end := fixed, fixed.Add(time.Hour)
	line, err := ca.Sign(Request{
		UserPublicKey: userKey(t), KeyID: "grant-abc alice", Principals: []string{"deploy"},
		ValidAfter: start, ValidBefore: end, SourceAddrs: []string{"10.8.0.2/32", "10.8.0.3/32"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(line, "ssh-ed25519-cert-v01@openssh.com ") {
		t.Fatalf("cert line = %q", line)
	}
	cert, err := Parse(line)
	if err != nil {
		t.Fatal(err)
	}
	if cert.CertType != ssh.UserCert || cert.KeyId != "grant-abc alice" {
		t.Fatalf("cert = %+v", cert)
	}
	if len(cert.ValidPrincipals) != 1 || cert.ValidPrincipals[0] != "deploy" {
		t.Fatalf("principals = %v", cert.ValidPrincipals)
	}
	if cert.ValidAfter != uint64(start.Unix()) || cert.ValidBefore != uint64(end.Unix()) {
		t.Fatalf("validity = %d..%d", cert.ValidAfter, cert.ValidBefore)
	}
	if cert.CriticalOptions["source-address"] != "10.8.0.2/32,10.8.0.3/32" {
		t.Fatalf("source-address = %q", cert.CriticalOptions["source-address"])
	}
	if _, ok := cert.Extensions["permit-pty"]; !ok {
		t.Fatal("permit-pty missing")
	}
	// The certificate verifies against the CA key - what sshd does with
	// TrustedUserCAKeys.
	checker := ssh.CertChecker{
		IsUserAuthority: func(auth ssh.PublicKey) bool {
			return string(auth.Marshal()) == string(ca.signer.PublicKey().Marshal())
		},
		Clock: func() time.Time { return fixed.Add(10 * time.Minute) },
	}
	if err := checker.CheckCert("deploy", cert); err != nil {
		t.Fatalf("cert does not verify: %v", err)
	}
	if err := checker.CheckCert("root", cert); err == nil {
		t.Fatal("cert valid for a principal it was not issued for")
	}
	checker.Clock = func() time.Time { return end.Add(time.Minute) }
	if err := checker.CheckCert("deploy", cert); err == nil {
		t.Fatal("expired cert accepted")
	}
}

func TestSignRejectsBadInput(t *testing.T) {
	ca, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	good := Request{UserPublicKey: userKey(t), KeyID: "k", Principals: []string{"deploy"}, ValidAfter: now, ValidBefore: now.Add(time.Hour)}
	cases := map[string]func(r *Request){
		"garbage key":     func(r *Request) { r.UserPublicKey = "not a key" },
		"no principals":   func(r *Request) { r.Principals = nil },
		"bad principal":   func(r *Request) { r.Principals = []string{"a b"} },
		"inverted window": func(r *Request) { r.ValidBefore = r.ValidAfter.Add(-time.Minute) },
		"ended window":    func(r *Request) { r.ValidAfter, r.ValidBefore = now.Add(-2*time.Hour), now.Add(-time.Hour) },
	}
	for name, mut := range cases {
		r := good
		r.Principals = append([]string(nil), good.Principals...)
		mut(&r)
		if _, err := ca.Sign(r); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// Signing a certificate again is refused.
	line, err := ca.Sign(good)
	if err != nil {
		t.Fatal(err)
	}
	r := good
	r.UserPublicKey = line
	if _, err := ca.Sign(r); err == nil {
		t.Fatal("re-signing a certificate accepted")
	}
}
