package ecdh

import (
	"crypto"
	"crypto/elliptic"
	"io"
	"math/big"
)

type ellipticECDH struct {
	ECDH
	curve elliptic.Curve
}

type ellipticPublicKey struct {
	elliptic.Curve
	X, Y *big.Int
}

type ellipticPrivateKey struct {
	D []byte
}

// NewEllipticECDH creates a new instance of ECDH with the given elliptic.Curve curve
// to use as the elliptical curve for elliptical curve diffie-hellman.
func NewEllipticECDH(curve elliptic.Curve) ECDH {
	return &ellipticECDH{
		curve: curve,
	}
}

func (e *ellipticECDH) GenerateKey(rand io.Reader) (priv crypto.PrivateKey, pub crypto.PublicKey, err error) {
	var (
		publicKey  = new(ellipticPublicKey)
		privateKey = new(ellipticPrivateKey)
	)

	// Set the curve to ECDH
	publicKey.Curve = e.curve

	// Generate the key
	privateKey.D, publicKey.X, publicKey.Y, err = elliptic.GenerateKey(e.curve, rand)
	if err != nil {
		return
	}

	// Return the keys
	return privateKey, publicKey, err
}

func (e *ellipticECDH) Marshal(p crypto.PublicKey) []byte {
	var pub = p.(*ellipticPublicKey)
	return elliptic.Marshal(e.curve, pub.X, pub.Y)
}

func (e *ellipticECDH) Unmarshal(data []byte) (pub crypto.PublicKey, valid bool) {
	var (
		key = new(ellipticPublicKey)
	)

	// Set the curve to ECDH
	key.Curve = e.curve

	// Unmarshal the keys
	key.X, key.Y = elliptic.Unmarshal(e.curve, data)

	// If both terms are != nil, set valid to true
	valid = key.X != nil && key.Y != nil
	return
}

// GenerateSharedSecret takes in a public key and a private key
// and generates a shared secret.
//
// RFC5903 Section 9 states we should only return x.
func (e *ellipticECDH) GenerateSharedSecret(privKey crypto.PrivateKey, pubKey crypto.PublicKey) (secret []byte, err error) {
	var (
		x *big.Int

		privateKey = privKey.(*ellipticPrivateKey)
		publicKey  = pubKey.(*ellipticPublicKey)
	)

	x, _ = e.curve.ScalarMult(publicKey.X, publicKey.Y, privateKey.D)
	secret = x.Bytes()
	return
}
