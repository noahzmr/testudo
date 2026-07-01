package wireguard

import (
	"fmt"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Keypair is a freshly generated Curve25519 WireGuard keypair. PrivateKey is
// secret material: it is returned to exactly one caller (client-side keygen in
// the browser, or the one-shot server-side config render) and must never be
// logged, persisted, or placed on the event bus. PublicKey is safe to store.
type Keypair struct {
	PrivateKey string // base64 - secret, handle once then drop
	PublicKey  string // base64 - public material
}

// GenerateKeypair produces a new Curve25519 keypair in-process via wgtypes - no
// shell-out to `wg genkey` (pure Go, no cgo). The private key exists only in the
// returned struct; callers are responsible for dropping it after single use.
func GenerateKeypair() (Keypair, error) {
	priv, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return Keypair{}, fmt.Errorf("generate private key: %w", err)
	}
	return Keypair{
		PrivateKey: priv.String(),
		PublicKey:  priv.PublicKey().String(),
	}, nil
}

// PublicKeyFor derives the public key for a given base64 private key without
// retaining the private key. Used by the browser client-side keygen path where
// only the public key is submitted to the server.
func PublicKeyFor(privateKey string) (string, error) {
	k, err := wgtypes.ParseKey(privateKey)
	if err != nil {
		return "", fmt.Errorf("parse private key: %w", err)
	}
	return k.PublicKey().String(), nil
}
