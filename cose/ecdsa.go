package cose

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"math/big"
)

func parseECDSA(alg int64, m map[int]interface{}) (interface{}, error) {
	var curve elliptic.Curve
	switch alg {
	case -7:
		curve = elliptic.P256()
	case -35:
		curve = elliptic.P384()
	case -36:
		curve = elliptic.P521()
	default:
		return nil, ErrUnsupportedAlgorithm
	}

	rawD, ok := m[-4]
	if !ok { // public key if there is no d
		return parseECDSAPublicKey(curve, m)
	}

	// otherwise, we have a private key

	dBytes, ok := rawD.([]byte)
	if !ok {
		return nil, ErrInvalidFormat
	}

	return &ecdsa.PrivateKey{
		D: big.NewInt(0).SetBytes(dBytes),
	}, nil
}

func parseECDSAPublicKey(curve elliptic.Curve, m map[int]interface{}) (*ecdsa.PublicKey, error) {
	rawX, ok := m[-2]
	if !ok {
		return nil, ErrInvalidFormat
	}
	xBytes, ok := rawX.([]byte)
	if !ok {
		return nil, ErrInvalidFormat
	}

	rawY, ok := m[-3]
	if !ok {
		return nil, ErrInvalidFormat
	}
	yBytes, ok := rawY.([]byte)
	if !ok {
		return nil, ErrInvalidFormat
	}

	x := big.NewInt(0).SetBytes(xBytes)
	y := big.NewInt(0).SetBytes(yBytes)

	return &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}, nil
}
