package cluster

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
)

// Secrets go through the replicated log sealed with the cluster key
// (AES-256-GCM). The key itself is never in the log: a member gets it when
// it joins, over the authenticated join connection, and keeps it in its own
// secret store.

// KeySize is the length of the cluster key.
const KeySize = 32

// NewKey makes a cluster key.
func NewKey() ([]byte, error) {
	k := make([]byte, KeySize)
	_, err := rand.Read(k)
	return k, err
}

func aead(key []byte) (cipher.AEAD, error) {
	if len(key) != KeySize {
		return nil, errors.New("cluster: the cluster key has the wrong length")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// seal encrypts value; name is bound in, so a sealed secret cannot be
// replayed under another name.
func seal(key []byte, name string, value []byte) ([]byte, error) {
	g, err := aead(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, g.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return g.Seal(nonce, nonce, value, []byte(name)), nil
}

func unseal(key []byte, name string, sealed []byte) ([]byte, error) {
	g, err := aead(key)
	if err != nil {
		return nil, err
	}
	if len(sealed) < g.NonceSize() {
		return nil, errors.New("cluster: sealed secret is too short")
	}
	return g.Open(nil, sealed[:g.NonceSize()], sealed[g.NonceSize():], []byte(name))
}
