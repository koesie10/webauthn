package protocol

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"

	"gopkg.in/square/go-jose.v2"
)

func init() {
	RegisterFormat("android-safetynet", verifyAndroidSafetynet)
}

type AndroidSafetyNetAttestionResponse struct {
	Nonce                      []byte   `json:"nonce"`
	TimestampMs                int64    `json:"timestampMs"`
	ApkPackageName             string   `json:"apkPackageName"`
	ApkDigestSha256            []byte   `json:"apkDigestSha256"`
	CtsProfileMatch            bool     `json:"ctsProfileMatch"`
	ApkCertificateDigestSha256 [][]byte `json:"apkCertificateDigestSha256"`
	BasicIntegrity             bool     `json:"basicIntegrity"`
}

func verifyAndroidSafetynet(a Attestation, clientDataHash []byte) error {
	// Verify that response is a valid SafetyNet response of version ver.
	rawVer, ok := a.AttStmt["ver"]
	if !ok {
		return ErrInvalidAttestation.WithDebug("missing ver for android-safetynet")
	}
	ver, ok := rawVer.(string)
	if !ok {
		return ErrInvalidAttestation.WithDebugf("invalid ver for android-safetynet, is of invalid type %T", rawVer)
	}

	if ver == "" {
		return ErrInvalidAttestation.WithDebug("invalid ver for android-safetynet")
	}

	rawResponse, ok := a.AttStmt["response"]
	if !ok {
		return ErrInvalidAttestation.WithDebug("missing response for android-safetynet")
	}
	responseBytes, ok := rawResponse.([]byte)
	if !ok {
		return ErrInvalidAttestation.WithDebugf("invalid response for android-safetynet, is of invalid type %T", responseBytes)
	}

	response, err := jose.ParseSigned(string(responseBytes))
	if err != nil {
		return ErrInvalidAttestation.WithDebugf("invalid response for android-safetynet: %v", err)
	}

	if len(response.Signatures) != 1 {
		return ErrInvalidAttestation.WithDebugf("invalid response for android-safetynet: more or less than 1 signature")
	}

	// Verify that the attestation certificate is issued to the hostname "attest.android.com"
	cert, err := response.Signatures[0].Protected.Certificates(x509.VerifyOptions{
		DNSName: "attest.android.com",
	})
	if err != nil {
		return ErrInvalidAttestation.WithDebugf("invalid response for android-safetynet: %v", err)
	}
	leaf := cert[0][0]

	payload, err := response.Verify(leaf.PublicKey)
	if err != nil {
		return ErrInvalidAttestation.WithDebugf("invalid response for android-safetynet: %v", err)
	}

	attestationResponse := AndroidSafetyNetAttestionResponse{}

	if err := json.Unmarshal(payload, &attestationResponse); err != nil {
		return ErrInvalidAttestation.WithDebugf("invalid response for android-safetynet: %v", err)
	}

	// Verify that the nonce in the response is identical to the SHA-256 hash of the concatenation of authenticatorData and clientDataHash.
	nonceBytes := append(a.AuthData.Raw, clientDataHash...)
	expectedNonce := sha256.Sum256(nonceBytes)

	if !bytes.Equal(expectedNonce[:], attestationResponse.Nonce) {
		return ErrInvalidAttestation.WithDebugf("invalid response for android-safetynet: invalid nonce")
	}

	// Verify that the ctsProfileMatch attribute in the payload of response is true.
	if !attestationResponse.CtsProfileMatch {
		return ErrInvalidAttestation.WithDebugf("invalid response for android-safetynet: does not match CTS profile")
	}

	// If successful, return attestation type Basic with the attestation trust path set to the above attestation certificate.
	return nil
}
