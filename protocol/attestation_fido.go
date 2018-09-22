package protocol

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
)

func init() {
	RegisterFormat("fido-u2f", verifyFIDO)
}

func verifyFIDO(a Attestation, clientDataHash []byte) error {
	rawSig, ok := a.AttStmt["sig"]
	if !ok {
		return ErrInvalidAttestation.WithDebug("missing sig for fido-u2f")
	}
	sig, ok := rawSig.([]byte)
	if !ok {
		return ErrInvalidAttestation.WithDebug("invalid sig for fido-u2f")
	}

	rawX5c, ok := a.AttStmt["x5c"]
	if !ok {
		return ErrInvalidAttestation.WithDebug("missing x5c for fido-u2f")
	}
	x5c, ok := rawX5c.([]interface{})
	if !ok {
		return ErrInvalidAttestation.WithDebug("invalid x5c for fido-u2f")
	}

	// Check that x5c has exactly one element
	if len(x5c) != 1 {
		return ErrInvalidAttestation.WithDebug("invalid x5c for fido-u2f")
	}

	// let attCert be that element
	attCert, ok := x5c[0].([]byte)
	if !ok {
		return ErrInvalidAttestation.WithDebug("invalid x5c for fido-u2f")
	}

	// Let certificate public key be the public key conveyed by attCert
	cert, err := x509.ParseCertificate(attCert)
	if err != nil {
		return ErrInvalidAttestation.WithDebugf("invalid x5c for fido-u2f: %v", err)
	}

	// If certificate public key is not an Elliptic Curve (EC) public key over the P-256 curve, terminate
	// this algorithm and return an appropriate error
	if cert.PublicKeyAlgorithm != x509.ECDSA {
		return ErrInvalidAttestation.WithDebug("x5c public key algorithm is invalid")
	}

	if cert.PublicKey.(*ecdsa.PublicKey).Curve != elliptic.P256() {
		return ErrInvalidAttestation.WithDebug("x5c signature algorithm is invalid")
	}

	publicKey, ok := a.AuthData.AttestedCredentialData.COSEKey.(*ecdsa.PublicKey)
	if !ok {
		return ErrInvalidAttestation.WithDebug("COSE public key algorithm is invalid")
	}

	x := publicKey.X.Bytes()
	y := publicKey.Y.Bytes()

	if len(x) != 32 {
		return ErrInvalidAttestation.WithDebug("COSE public key x is invalid")
	}
	if len(y) != 32 {
		return ErrInvalidAttestation.WithDebug("COSE public key y is invalid")
	}

	// Let publicKeyU2F be the concatenation 0x04 || x || y
	publicKeyU2F := []byte{0x04}
	publicKeyU2F = append(publicKeyU2F, x...)
	publicKeyU2F = append(publicKeyU2F, y...)

	// Let verificationData be the concatenation of (0x00 || rpIdHash || clientDataHash || credentialId || publicKeyU2F)
	verificationData := []byte{0x00}
	verificationData = append(verificationData, a.AuthData.RPIDHash...)
	verificationData = append(verificationData, clientDataHash...)
	verificationData = append(verificationData, a.AuthData.AttestedCredentialData.CredentialID...)
	verificationData = append(verificationData, publicKeyU2F...)

	// Verify the sig using verificationData and certificate public key per [SEC1].
	if err := cert.CheckSignature(x509.ECDSAWithSHA256, verificationData, sig); err != nil {
		return ErrInvalidSignature.WithDebug(err.Error())
	}

	return nil
}
