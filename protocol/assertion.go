package protocol

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
)

// AssertionResponse contains the attributes that are returned to the caller when a new assertion is requested.
// https://www.w3.org/TR/webauthn/#publickeycredential
type AssertionResponse struct {
	PublicKeyCredential
	// This attribute contains the authenticator's response to the client’s request to generate an authentication assertion.
	Response AuthenticatorAssertionResponse `json:"response"`
}

// ParsedAssertionResponse is a parsed version of AssertionResponse.
// https://www.w3.org/TR/webauthn/#publickeycredential
type ParsedAssertionResponse struct {
	ParsedPublicKeyCredential
	// This attribute contains the authenticator's response to the client’s request to generate an authentication assertion.
	Response ParsedAuthenticatorAssertionResponse
	// RawResponse contains the unparsed AssertionResponse.
	RawResponse AssertionResponse
}

// The AuthenticatorAssertionResponse interface represents an authenticator's response to a client’s request for
// generation of a new authentication assertion given the WebAuthn Relying Party's challenge and OPTIONAL list of
// credentials it is aware of. This response contains a cryptographic signature proving possession of the credential
// private key, and optionally evidence of user consent to a specific transaction.
// https://www.w3.org/TR/webauthn/#authenticatorassertionresponse
type AuthenticatorAssertionResponse struct {
	AuthenticatorResponse
	// This attribute contains the authenticator data returned by the authenticator. See §6.1 Authenticator data.
	AuthenticatorData []byte `json:"authenticatorData"`
	// This attribute contains the raw signature returned from the authenticator. See §6.3.3 The
	// authenticatorGetAssertion operation.
	Signature []byte `json:"signature"`
	// This attribute contains the user handle returned from the authenticator, or null if the authenticator did not
	// return a user handle. See §6.3.3 The authenticatorGetAssertion operation.
	UserHandle []byte `json:"userHandle,omitempty"`
}

// ParsedAuthenticatorAssertionResponse is a parsed version of AuthenticatorAssertionResponse.
// https://www.w3.org/TR/webauthn/#authenticatorassertionresponse
type ParsedAuthenticatorAssertionResponse struct {
	ParsedAuthenticatorResponse
	// This attribute contains the authenticator data returned by the authenticator. See §6.1 Authenticator data.
	AuthData AuthenticatorData
	// This attribute contains the raw signature returned from the authenticator. See §6.3.3 The
	// authenticatorGetAssertion operation.
	Signature []byte
	// This attribute contains the user handle returned from the authenticator, or null if the authenticator did not
	// return a user handle. See §6.3.3 The authenticatorGetAssertion operation.
	UserHandle []byte
}

// ParseAssertionResponse will parse a raw AssertionResponse as supplied by a client to a ParsedAssertionResponse
// that may be used by clients to examine data. If the data is invalid, an error is returned, usually of the type
// Error.
func ParseAssertionResponse(p AssertionResponse) (ParsedAssertionResponse, error) {
	r := ParsedAssertionResponse{}
	r.ID, r.RawID, r.Type = p.ID, p.RawID, p.Type
	r.Response.Signature = p.Response.Signature
	r.RawResponse = p

	// 6. Let C, the client data claimed as used for the signature, be the result of running an implementation-specific
	// JSON parser on JSONtext.
	if err := json.Unmarshal(p.Response.ClientDataJSON, &r.Response.ClientData); err != nil {
		return ParsedAssertionResponse{}, ErrInvalidRequest.WithDebug(err.Error()).WithHint("Unable to parse client data")
	}

	if err := r.Response.AuthData.UnmarshalBinary(p.Response.AuthenticatorData); err != nil {
		return ParsedAssertionResponse{}, ErrInvalidRequest.WithDebug(err.Error()).WithHint("Unable to parse auth data")
	}

	return r, nil
}

// IsValidAssertion may be used to check whether an assertion is valid. If originalChallenge is nil, the challenge value
// will not be checked (INSECURE). If relyingPartyID is empty, the relying party hash will not be checked (INSECURE). If
// relyingPartyOrigin is empty, the relying party origin will not be checked (INSEUCRE).
// If cert is nil, the hash will not be checked (INSECURE). Before calling this method, clients should execute the
// following steps: If the allowCredentials option was given when this authentication ceremony was initiated, verify that
// credential.id identifies one of the public key credentials that were listed in allowCredentials; If
// credential.response.userHandle is present, verify that the user identified by this value is the owner of the public
// key credential identified by credential.id. If the data is invalid, an error is returned, usually of the type
// Error.
func IsValidAssertion(p ParsedAssertionResponse, originalChallenge []byte, relyingPartyID, relyingPartyOrigin string, cert *x509.Certificate) (bool, error) {
	// Check the client data, i.e. steps 7-10
	if err := p.Response.ClientData.IsValid("webauthn.get", originalChallenge, relyingPartyOrigin); err != nil {
		return false, err
	}

	// Check the auth data, i.e. steps 10-13
	if err := p.Response.AuthData.IsValid(relyingPartyID); err != nil {
		return false, err
	}

	if cert != nil {
		// 15. Let hash be the result of computing a hash over the cData using SHA-256.
		clientDataHash := sha256.Sum256(p.RawResponse.Response.ClientDataJSON)

		// 16. Using the credential public key looked up in step 3, verify that sig is a valid signature over the binary
		// concatenation of authData and hash.
		verificationData := append(p.RawResponse.Response.AuthenticatorData, clientDataHash[:]...)
		if err := cert.CheckSignature(x509.ECDSAWithSHA256, verificationData, p.Response.Signature); err != nil {
			return false, ErrInvalidSignature.WithDebug(err.Error())
		}
	}

	// TODO: 17. If the signature counter value authData.signCount is nonzero or the value stored in conjunction with
	// credential’s id attribute is nonzero, then run the following sub-step: ...

	return true, nil
}
