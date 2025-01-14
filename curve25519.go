package ecdh

import (
	"crypto"
	"io"

	"golang.org/x/crypto/curve25519"
)

type curve25519ECDH struct {
	ECDH
}

// NewCurve25519ECDH creates a new ECDH instance that uses djb's curve25519
// elliptical curve.
func NewCurve25519ECDH() ECDH {
	return &curve25519ECDH{}
}

func (e *curve25519ECDH) GenerateKey(rand io.Reader) (privateKey crypto.PrivateKey, publicKey crypto.PublicKey, err error) {
	var pub, priv [32]byte

	_, err = io.ReadFull(rand, priv[:])
	if err != nil {
		return
	}

	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64

	curve25519.ScalarBaseMult(&pub, &priv)

	privateKey = &priv
	publicKey = &pub
	return
}

func (e *curve25519ECDH) Marshal(p crypto.PublicKey) []byte {
	return p.(*[32]byte)[:]
}

func (e *curve25519ECDH) Unmarshal(data []byte) (crypto.PublicKey, bool) {
	var pub [32]byte
	if len(data) != 32 {
		return nil, false
	}

	copy(pub[:], data)
	return &pub, true
}

func (e *curve25519ECDH) GenerateSharedSecret(privKey crypto.PrivateKey, pubKey crypto.PublicKey) (secret []byte, err error) {
	return curve25519.X25519(
		privKey.(*[32]byte)[:],
		pubKey.(*[32]byte)[:],
	)
}
