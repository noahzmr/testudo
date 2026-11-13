package web

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// TLSConfig selects how the Web UI serves HTTPS. Zero value = plain HTTP (the
// pre-identity behaviour; fine on a trusted LAN, not fine once this process
// owns the firewall and the access grants).
type TLSConfig struct {
	CertFile string // operator-provided certificate chain (PEM)
	KeyFile  string // operator-provided private key (PEM)
	// Auto generates a self-signed ECDSA P-256 certificate into Dir on first
	// use (server.crt / server.key, 0600) and reuses it afterwards. Browsers
	// warn once; the fingerprint is printed at startup for pinning.
	Auto bool
	Dir  string
	// Hosts are the SANs for the self-signed certificate (hostname, listen
	// address, "localhost" and loopback are always included).
	Hosts []string
}

// Enabled reports whether HTTPS is requested in any form.
func (c TLSConfig) Enabled() bool { return c.Auto || (c.CertFile != "" && c.KeyFile != "") }

// resolve returns the cert/key paths to serve with, generating a self-signed
// pair when Auto is set and none exists yet.
func (c TLSConfig) resolve() (cert, key string, err error) {
	if c.CertFile != "" && c.KeyFile != "" {
		return c.CertFile, c.KeyFile, nil
	}
	if !c.Auto {
		return "", "", nil
	}
	dir := c.Dir
	if dir == "" {
		return "", "", fmt.Errorf("tls auto: state directory not set")
	}
	cert = filepath.Join(dir, "server.crt")
	key = filepath.Join(dir, "server.key")
	if _, err := os.Stat(cert); err == nil {
		if _, err := os.Stat(key); err == nil {
			return cert, key, nil
		}
	}
	if err := generateSelfSigned(cert, key, c.Hosts); err != nil {
		return "", "", err
	}
	return cert, key, nil
}

// generateSelfSigned writes a 10-year self-signed ECDSA P-256 certificate.
func generateSelfSigned(certPath, keyPath string, hosts []string) error {
	if err := os.MkdirAll(filepath.Dir(certPath), 0o700); err != nil {
		return err
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return err
	}
	hostname, _ := os.Hostname()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: firstNonEmpty(hostname, "testudo"), Organization: []string{"Testudo"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}
	if hostname != "" {
		tmpl.DNSNames = append(tmpl.DNSNames, hostname)
	}
	for _, h := range hosts {
		if h == "" {
			continue
		}
		if ip := net.ParseIP(h); ip != nil {
			if !ip.IsUnspecified() {
				tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
			}
			continue
		}
		tmpl.DNSNames = append(tmpl.DNSNames, h)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return err
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return err
	}
	return os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
}

// certFingerprint returns the SHA-256 fingerprint of the leaf certificate for
// the startup banner, so an operator can pin a self-signed cert.
func certFingerprint(certPath string) string {
	data, err := os.ReadFile(certPath)
	if err != nil {
		return ""
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return ""
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(c.Raw)
	out := make([]byte, 0, len(sum)*3)
	for i, b := range sum {
		if i > 0 {
			out = append(out, ':')
		}
		out = append(out, "0123456789ABCDEF"[b>>4], "0123456789ABCDEF"[b&0x0f])
	}
	return string(out)
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
