// Package pki is the appliance's internal certificate authority: it issues
// server certificates for services that are published without a public
// certificate. The CA key and every issued key live in the node's secret
// store; only certificates leave it.
package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"

	"github.com/noahzmr/testudo/internal/secrets"
)

const (
	caKeyEntry  = "internal-ca-key"
	caCertEntry = "internal-ca-cert"
	// LeafValidity stays under the 398 days that clients accept.
	LeafValidity = 397 * 24 * time.Hour
	caValidity   = 10 * 365 * 24 * time.Hour
)

// CA issues certificates from a key in the secret store.
type CA struct {
	Secrets secrets.Store
	// Now is the clock; nil means time.Now.
	Now func() time.Time
	// Name tells authorities in one secret store apart: it is part of the
	// entry names and of the certificate's subject. Empty is the authority
	// for published services.
	Name string
}

func (c CA) entries() (key, cert, subject string) {
	if c.Name == "" {
		return caKeyEntry, caCertEntry, "Testudo internal CA"
	}
	return c.Name + "-ca-key", c.Name + "-ca-cert", "Testudo " + c.Name + " CA"
}

func (c CA) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func serial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
}

func pemBlock(typ string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
}

// load returns the CA, creating it on first use.
func (c CA) load() (*x509.Certificate, *ecdsa.PrivateKey, []byte, error) {
	caKeyEntry, caCertEntry, subject := c.entries()
	certPEM, err := c.Secrets.Get(caCertEntry)
	if err == nil {
		keyPEM, err := c.Secrets.Get(caKeyEntry)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("pki: the CA certificate exists but its key does not: %w", err)
		}
		cb, _ := pem.Decode(certPEM)
		kb, _ := pem.Decode(keyPEM)
		if cb == nil || kb == nil {
			return nil, nil, nil, errors.New("pki: the stored CA is not PEM")
		}
		cert, err := x509.ParseCertificate(cb.Bytes)
		if err != nil {
			return nil, nil, nil, err
		}
		key, err := x509.ParseECPrivateKey(kb.Bytes)
		return cert, key, certPEM, err
	}
	if !errors.Is(err, secrets.ErrNotFound) {
		return nil, nil, nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	sn, err := serial()
	if err != nil {
		return nil, nil, nil, err
	}
	now := c.now()
	tmpl := &x509.Certificate{SerialNumber: sn, Subject: pkix.Name{CommonName: subject},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(caValidity), IsCA: true, BasicConstraintsValid: true,
		MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, nil, err
	}
	// The key first: a CA certificate without its key is useless, the other
	// way round is harmless.
	if err := c.Secrets.Put(caKeyEntry, pemBlock("EC PRIVATE KEY", keyDER)); err != nil {
		return nil, nil, nil, err
	}
	certPEM = pemBlock("CERTIFICATE", der)
	if err := c.Secrets.Put(caCertEntry, certPEM); err != nil {
		return nil, nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	return cert, key, certPEM, err
}

// Certificate returns the CA certificate in PEM, for clients to trust.
func (c CA) Certificate() ([]byte, error) {
	_, _, pemBytes, err := c.load()
	return pemBytes, err
}

// Issued is a new server certificate.
type Issued struct {
	// ChainPEM is the certificate followed by the CA certificate.
	ChainPEM string
	// KeyPEM is the private key. The caller stores it in the secret store
	// and nowhere else.
	KeyPEM   []byte
	NotAfter time.Time
}

// Issue creates a key and a server certificate for the given names. A name
// may be a host name, a wildcard or an IP address.
func (c CA) Issue(names []string) (Issued, error) {
	if len(names) == 0 {
		return Issued{}, errors.New("pki: a certificate needs at least one name")
	}
	caCert, caKey, caPEM, err := c.load()
	if err != nil {
		return Issued{}, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Issued{}, err
	}
	sn, err := serial()
	if err != nil {
		return Issued{}, err
	}
	now := c.now()
	tmpl := &x509.Certificate{SerialNumber: sn, Subject: pkix.Name{CommonName: names[0]},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(LeafValidity),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	for _, n := range names {
		if ip := net.ParseIP(n); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, strings.ToLower(n))
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		return Issued{}, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return Issued{}, err
	}
	return Issued{ChainPEM: string(pemBlock("CERTIFICATE", der)) + string(caPEM),
		KeyPEM: pemBlock("EC PRIVATE KEY", keyDER), NotAfter: tmpl.NotAfter}, nil
}

// NotAfter returns the expiry of the first certificate in a PEM chain.
func NotAfter(chainPEM string) (time.Time, error) {
	block, _ := pem.Decode([]byte(chainPEM))
	if block == nil {
		return time.Time{}, errors.New("pki: not a PEM certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, err
	}
	return cert.NotAfter, nil
}

// CheckPair reports whether a private key in PEM belongs to the first
// certificate of a chain. It is how an imported key is validated before it
// is stored.
func CheckPair(chainPEM string, keyPEM []byte) error {
	block, _ := pem.Decode([]byte(chainPEM))
	if block == nil {
		return errors.New("the certificate chain is not PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("the certificate cannot be read: %w", err)
	}
	kb, _ := pem.Decode(keyPEM)
	if kb == nil {
		return errors.New("the private key is not PEM")
	}
	var key any
	if key, err = x509.ParsePKCS8PrivateKey(kb.Bytes); err != nil {
		if key, err = x509.ParseECPrivateKey(kb.Bytes); err != nil {
			if key, err = x509.ParsePKCS1PrivateKey(kb.Bytes); err != nil {
				return errors.New("the private key is in no supported format (PKCS#8, EC or RSA)")
			}
		}
	}
	pub, ok := key.(crypto.Signer)
	if !ok {
		return errors.New("the private key type is not supported")
	}
	type equaler interface{ Equal(crypto.PublicKey) bool }
	if cp, ok := cert.PublicKey.(equaler); !ok || !cp.Equal(pub.Public()) {
		return errors.New("the private key does not belong to the certificate")
	}
	return nil
}

// SignRequest issues a certificate for a key that stays where it was made:
// the requester sends a signing request, never its key. The certificate is
// good for both ends of a connection (members of a cluster dial and accept)
// and carries cn as its subject, whatever the request asked for; the
// addresses and names come from the request. The serial is returned so the
// certificate can be revoked.
func (c CA) SignRequest(csrDER []byte, cn string, validity time.Duration) (certPEM []byte, serialHex string, err error) {
	req, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, "", fmt.Errorf("pki: signing request: %w", err)
	}
	if err := req.CheckSignature(); err != nil {
		return nil, "", fmt.Errorf("pki: signing request: %w", err)
	}
	caCert, caKey, caPEM, err := c.load()
	if err != nil {
		return nil, "", err
	}
	sn, err := serial()
	if err != nil {
		return nil, "", err
	}
	now := c.now()
	tmpl := &x509.Certificate{SerialNumber: sn, Subject: pkix.Name{CommonName: cn},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(validity),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:    req.DNSNames, IPAddresses: req.IPAddresses}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, req.PublicKey, caKey)
	if err != nil {
		return nil, "", err
	}
	return append(pemBlock("CERTIFICATE", der), caPEM...), sn.Text(16), nil
}

// NewRequest makes a key and a signing request for it. names are host
// names and IP addresses the certificate should be valid for.
func NewRequest(cn string, names []string) (keyPEM, csrDER []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}
	for _, n := range names {
		if ip := net.ParseIP(n); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else if n != "" {
			tmpl.DNSNames = append(tmpl.DNSNames, strings.ToLower(n))
		}
	}
	csrDER, err = x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pemBlock("EC PRIVATE KEY", keyDER), csrDER, nil
}
