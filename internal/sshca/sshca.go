// Package sshca is a minimal SSH user certificate authority for brokered
// shell access: instead of handing a user a standing key for a target, Testudo
// signs the user's own public key with a certificate that is valid exactly for
// the grant window, for exactly the login the resource allows, and only from
// the user's tunnel addresses. Targets trust the CA (`TrustedUserCAKeys`), so
// no per-host authorized_keys churn and nothing to revoke afterwards - the
// certificate simply expires with the grant.
//
// Secrets rule: the CA private key is generated in-process, written 0600, and
// never logged, exported or placed on the event bus. Only the public key leaves
// this package.
package sshca

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	keyFile = "ca"     // OpenSSH-format private key, 0600
	pubFile = "ca.pub" // authorized_keys-format public key
)

// CA signs user certificates with one Ed25519 key kept on disk.
type CA struct {
	mu     sync.Mutex
	dir    string
	signer ssh.Signer
	now    func() time.Time
}

// Open loads the CA from dir, generating a fresh Ed25519 key on first use.
func Open(dir string) (*CA, error) {
	if dir == "" {
		return nil, errors.New("sshca: directory required")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	ca := &CA{dir: dir, now: time.Now}
	raw, err := os.ReadFile(filepath.Join(dir, keyFile))
	switch {
	case err == nil:
		signer, perr := ssh.ParsePrivateKey(raw)
		if perr != nil {
			return nil, fmt.Errorf("sshca: parse CA key: %w", perr)
		}
		ca.signer = signer
	case os.IsNotExist(err):
		if err := ca.generate(); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("sshca: read CA key: %w", err)
	}
	return ca, nil
}

// generate creates and persists a new Ed25519 CA key pair.
func (c *CA) generate() error {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	block, err := ssh.MarshalPrivateKey(priv, "testudo ssh ca")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(c.dir, keyFile), pem.EncodeToMemory(block), 0o600); err != nil {
		return err
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(c.dir, pubFile), ssh.MarshalAuthorizedKey(sshPub), 0o644); err != nil {
		return err
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return err
	}
	c.signer = signer
	return nil
}

// PublicKey returns the CA public key in authorized_keys format - the line to
// put in the targets' TrustedUserCAKeys file.
func (c *CA) PublicKey() string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(c.signer.PublicKey())))
}

// Fingerprint returns the SHA-256 fingerprint of the CA key.
func (c *CA) Fingerprint() string { return ssh.FingerprintSHA256(c.signer.PublicKey()) }

// Request describes one certificate to issue.
type Request struct {
	UserPublicKey string    // the user's own public key, authorized_keys format
	KeyID         string    // free text recorded in the cert; use the grant id + user
	Principals    []string  // logins the cert is valid for (the resource's login)
	ValidAfter    time.Time // grant start
	ValidBefore   time.Time // grant end
	SourceAddrs   []string  // peer tunnel addresses (CIDRs) the cert may be used from
}

// Sign issues a user certificate. The certificate is returned in
// authorized_keys format (OpenSSH *-cert.pub); it contains no secret.
func (c *CA) Sign(req Request) (string, error) {
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(strings.TrimSpace(req.UserPublicKey)))
	if err != nil {
		return "", fmt.Errorf("sshca: user public key: %w", err)
	}
	if _, isCert := pub.(*ssh.Certificate); isCert {
		return "", errors.New("sshca: a certificate cannot be signed again; supply the plain public key")
	}
	if len(req.Principals) == 0 {
		return "", errors.New("sshca: at least one principal required")
	}
	for _, p := range req.Principals {
		if strings.TrimSpace(p) == "" || strings.ContainsAny(p, " \t\n,") {
			return "", fmt.Errorf("sshca: invalid principal %q", p)
		}
	}
	if req.ValidBefore.IsZero() || !req.ValidBefore.After(req.ValidAfter) {
		return "", errors.New("sshca: validity window must end after it starts")
	}
	now := c.now()
	if !req.ValidBefore.After(now) {
		return "", errors.New("sshca: validity window already ended")
	}
	var serial [8]byte
	if _, err := rand.Read(serial[:]); err != nil {
		return "", err
	}
	cert := &ssh.Certificate{
		Key:             pub,
		Serial:          uint64(serial[0])<<56 | uint64(serial[1])<<48 | uint64(serial[2])<<40 | uint64(serial[3])<<32 | uint64(serial[4])<<24 | uint64(serial[5])<<16 | uint64(serial[6])<<8 | uint64(serial[7]),
		CertType:        ssh.UserCert,
		KeyId:           req.KeyID,
		ValidPrincipals: append([]string(nil), req.Principals...),
		ValidAfter:      uint64(req.ValidAfter.Unix()),
		ValidBefore:     uint64(req.ValidBefore.Unix()),
		Permissions: ssh.Permissions{
			CriticalOptions: map[string]string{},
			Extensions: map[string]string{
				"permit-pty":              "",
				"permit-user-rc":          "",
				"permit-agent-forwarding": "",
			},
		},
	}
	if len(req.SourceAddrs) > 0 {
		cert.Permissions.CriticalOptions["source-address"] = strings.Join(req.SourceAddrs, ",")
	}
	c.mu.Lock()
	err = cert.SignCert(rand.Reader, c.signer)
	c.mu.Unlock()
	if err != nil {
		return "", fmt.Errorf("sshca: sign: %w", err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(cert))), nil
}

// Parse decodes a certificate produced by Sign (for tests and display).
func Parse(certLine string) (*ssh.Certificate, error) {
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(strings.TrimSpace(certLine)))
	if err != nil {
		return nil, err
	}
	cert, ok := pub.(*ssh.Certificate)
	if !ok {
		return nil, errors.New("not a certificate")
	}
	return cert, nil
}
