package pki

import (
	"crypto/tls"
	"crypto/x509"
	"strings"
	"testing"
	"time"

	"github.com/noahzmr/testudo/internal/secrets"
)

func TestIssueVerifiesAgainstTheCA(t *testing.T) {
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	ca := CA{Secrets: secrets.Store{Dir: t.TempDir()}, Now: func() time.Time { return now }}
	issued, err := ca.Issue([]string{"app.example.com", "*.apps.example.com", "10.0.0.5"})
	if err != nil {
		t.Fatal(err)
	}
	caPEM, err := ca.Certificate()
	if err != nil {
		t.Fatal(err)
	}
	// The pair loads as a TLS certificate and its chain ends at the CA.
	pair, err := tls.X509KeyPair([]byte(issued.ChainPEM), issued.KeyPEM)
	if err != nil {
		t.Fatalf("issued pair: %v", err)
	}
	leaf, _ := x509.ParseCertificate(pair.Certificate[0])
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(caPEM)
	for _, name := range []string{"app.example.com", "x.apps.example.com", "10.0.0.5"} {
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: name, CurrentTime: now.Add(time.Hour)}); err != nil {
			t.Errorf("verify %s: %v", name, err)
		}
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: "other.example.com", CurrentTime: now.Add(time.Hour)}); err == nil {
		t.Error("verified for a name it was not issued for")
	}
	if !issued.NotAfter.Equal(now.Add(LeafValidity)) {
		t.Errorf("not after %v", issued.NotAfter)
	}
	if got, err := NotAfter(issued.ChainPEM); err != nil || !got.Equal(issued.NotAfter.Truncate(time.Second)) {
		t.Errorf("NotAfter: %v %v", got, err)
	}
	if leaf.IsCA {
		t.Error("the issued certificate is a CA")
	}

	// A second issue uses the same CA; the CA is created once.
	again, _ := ca.Issue([]string{"b.example.com"})
	caPEM2, _ := ca.Certificate()
	if string(caPEM) != string(caPEM2) || again.ChainPEM == issued.ChainPEM {
		t.Error("the CA changed between two issues, or two issues gave the same certificate")
	}
	// The pair check tells a matching key from a foreign one.
	if err := CheckPair(issued.ChainPEM, issued.KeyPEM); err != nil {
		t.Errorf("matching pair: %v", err)
	}
	if err := CheckPair(issued.ChainPEM, again.KeyPEM); err == nil || !strings.Contains(err.Error(), "does not belong") {
		t.Errorf("foreign key: %v", err)
	}
	if err := CheckPair("nonsense", issued.KeyPEM); err == nil {
		t.Error("nonsense chain accepted")
	}
	if _, err := ca.Issue(nil); err == nil {
		t.Error("certificate without names issued")
	}
}
