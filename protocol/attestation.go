package protocol

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"

	"github.com/ugorji/go/codec"
)

// AttestationResponse contains the attributes that are returned to the caller when a new credential is created.
// https://www.w3.org/TR/webauthn/#publickeycredential
type AttestationResponse struct {
	PublicKeyCredential
	// This attribute contains the authenticator's response to the client’s request to create a public key credential.
	Response AuthenticatorAttestationResponse `json:"response"`
}

// ParsedAttestationResponse is a parsed version of AttestationResponse
// https://www.w3.org/TR/webauthn/#publickeycredential
type ParsedAttestationResponse struct {
	ParsedPublicKeyCredential
	// This attribute contains the authenticator's response to the client’s request to create a public key credential.
	Response ParsedAuthenticatorAttestationResponse
	// RawResponse contains the unparsed AttestationResponse.
	RawResponse AttestationResponse
}

// The AuthenticatorAttestationResponse interface represents the authenticator's response to a client’s request for the
// creation of a new public key credential. It contains information about the new credential that can be used to
// identify it for later use, and metadata that can be used by the WebAuthn Relying Party to assess the characteristics
// of the credential during registration.
// https://www.w3.org/TR/webauthn/#authenticatorattestationresponse
type AuthenticatorAttestationResponse struct {
	AuthenticatorResponse
	// This attribute contains an attestation object, which is opaque to, and cryptographically protected against
	// tampering by, the client. The attestation object contains both authenticator data and an attestation statement.
	// The former contains the AAGUID, a unique credential ID, and the credential public key. The contents of the
	// attestation statement are determined by the attestation statement format used by the authenticator. It also
	// contains any additional information that the Relying Party's server requires to validate the attestation
	// statement, as well as to decode and validate the authenticator data along with the JSON-serialized client data.
	// For more details, see §6.4 Attestation, §6.4.4 Generating an Attestation Object, and Figure 5.
	AttestationObject []byte `json:"attestationObject"`
}

// ParsedAuthenticatorAttestationResponse is a parsed version of AuthenticatorAttestationResponse
// https://www.w3.org/TR/webauthn/#authenticatorattestationresponse
type ParsedAuthenticatorAttestationResponse struct {
	ParsedAuthenticatorResponse
	// This attribute contains an attestation object, which is opaque to, and cryptographically protected against
	// tampering by, the client. The attestation object contains both authenticator data and an attestation statement.
	// The former contains the AAGUID, a unique credential ID, and the credential public key. The contents of the
	// attestation statement are determined by the attestation statement format used by the authenticator. It also
	// contains any additional information that the Relying Party's server requires to validate the attestation
	// statement, as well as to decode and validate the authenticator data along with the JSON-serialized client data.
	// For more details, see §6.4 Attestation, §6.4.4 Generating an Attestation Object, and Figure 5.
	Attestation Attestation
}

// Attestation represents the attestionObject. An important component of the attestation object is the attestation
// statement. This is a specific type of  signed data object, containing statements about a public key credential itself
// and the authenticator that created it. It contains an attestation signature created using the key of the attesting
// authority (except for the case of self attestation, when it is created using the credential private key). In order to
// correctly  interpret an attestation statement, a Relying Party needs to understand these two aspects of attestation:
// https://www.w3.org/TR/webauthn/#attestation-object
type Attestation struct {
	Fmt      string                 `json:"fmt"`
	AuthData AuthenticatorData      `json:"authData"`
	AttStmt  map[string]interface{} `json:"attStmt"`
}

// ParseAttestationResponse will parse a raw AttestationResponse as supplied by a client to a ParsedAttestationResponse
// that may be used by clients to examine data. If the data is invalid, an error is returned, usually of the type
// Error.
func ParseAttestationResponse(p AttestationResponse) (ParsedAttestationResponse, error) {
	r := ParsedAttestationResponse{}
	r.ID, r.RawID, r.Type = p.ID, p.RawID, p.Type
	r.RawResponse = p

	// 2. Let C, the client data claimed as collected during the credential creation, be the result of running an
	// implementation-specific JSON parser on JSONtext.
	if err := json.Unmarshal(p.Response.ClientDataJSON, &r.Response.ClientData); err != nil {
		return ParsedAttestationResponse{}, ErrInvalidRequest.WithDebug(err.Error()).WithHint("Unable to parse client data")
	}

	cbor := codec.CborHandle{}

	// 8. Perform CBOR decoding on the attestationObject field of the AuthenticatorAttestationResponse structure to
	// obtain the attestation statement format fmt, the authenticator data authData, and the attestation statement
	// attStmt.
	if err := codec.NewDecoder(bytes.NewReader(p.Response.AttestationObject), &cbor).Decode(&r.Response.Attestation); err != nil {
		return ParsedAttestationResponse{}, ErrInvalidRequest.WithDebug(err.Error()).WithHint("Unable to parse attestation")
	}

	return r, nil
}

// IsValidAttestation may be used to check whether an attestation is valid. If originalChallenge is nil, the challenge value
// will not be checked (INSECURE). If relyingPartyID is empty, the relying party ID hash will not be checked (INSECURE). If
// relyingPartyOrigin is empty, the relying party origin will not be checked (INSEUCRE).
// If the data is invalid, an error is returned, usually of the type Error.
func IsValidAttestation(p ParsedAttestationResponse, originalChallenge []byte, relyingPartyID, relyingPartyOrigin string) (bool, error) {
	// Check the client data, i.e. steps 3-6
	if err := p.Response.ClientData.IsValid("webauthn.create", originalChallenge, relyingPartyOrigin); err != nil {
		return false, err
	}

	// 7. Compute the hash of response.clientDataJSON using SHA-256
	clientDataHash := sha256.Sum256(p.RawResponse.Response.ClientDataJSON)

	// Check the attestation, i.e. steps 9-14
	if err := p.Response.Attestation.IsValid(relyingPartyID, clientDataHash[:]); err != nil {
		return false, err
	}

	return true, nil
}

// IsValid checks whether the Attestation is valid. If relyingPartyID is empty, the relying party ID hash will not be
// checked (INSEUCRE). To register a new attestation type, use RegisterFormat. If the data is invalid, an error is
// returned, usually of the type Error.
func (a Attestation) IsValid(relyingPartyID string, clientDataHash []byte) error {
	// Check the auth data, i.e. steps 9-11
	if err := a.AuthData.IsValid(relyingPartyID); err != nil {
		return err
	}

	// 13. Determine the attestation statement format by performing a USASCII case-sensitive match on fmt against the set
	// of supported WebAuthn Attestation Statement Format Identifier values.
	format, ok := attestationFormats[a.Fmt]
	if !ok {
		return ErrUnsupportedAttestationFormat.WithDebugf("The attestation format %q is unknown", a.Fmt)
	}

	// 14. Verify that attStmt is a correct attestation statement, conveying a valid attestation signature, by using the
	// attestation statement format fmt’s verification procedure given attStmt, authData and the hash of the serialized
	// client data computed in step 7.
	if err := format(a, clientDataHash); err != nil {
		return err
	}

	// NOTE: However, if permitted by policy, the Relying Party MAY register the credential ID and credential public
	// key but treat the credential as one with self attestation (see §6.4.3 Attestation Types). If doing so, the
	// Relying Party is asserting there is no cryptographic proof that the public key credential has been generated
	// by a particular authenticator model. See [FIDOSecRef] and [UAFProtocol] for a more detailed discussion.

	return nil
}
