package protocol

import (
	"bytes"
	"crypto/sha256"
	"encoding"
	"encoding/base64"
	"encoding/binary"
	"fmt"

	"github.com/koesie10/webauthn/cose"
)

// The PublicKeyCredential interface inherits from Credential [CREDENTIAL-MANAGEMENT-1], and contains the attributes
// that are returned to the caller when a new credential is created, or a new assertion is requested.
// See AttestationResponse and AssertionResponse
// https://www.w3.org/TR/webauthn/#publickeycredential
type PublicKeyCredential struct {
	// This attribute is inherited from Credential, though PublicKeyCredential overrides Credential's getter, instead
	// returning the base64url encoding of the data contained in the object’s [[identifier]] internal slot.
	ID string `json:"id"`
	// This attribute returns the ArrayBuffer contained in the [[identifier]] internal slot.
	RawID []byte `json:"rawId"`
	// The PublicKeyCredential interface object's [[type]] internal slot's value is the string "public-key".
	Type string `json:"type"`
}

// ParsedPublicKeyCredential is a parsed version of PublicKeyCredential
// https://www.w3.org/TR/webauthn/#publickeycredential
type ParsedPublicKeyCredential struct {
	// This attribute is inherited from Credential, though PublicKeyCredential overrides Credential's getter, instead
	// returning the base64url encoding of the data contained in the object’s [[identifier]] internal slot.
	ID string
	// This attribute returns the ArrayBuffer contained in the [[identifier]] internal slot.
	RawID []byte
	// The PublicKeyCredential interface object's [[type]] internal slot's value is the string "public-key".
	Type string
}

// AuthenticatorResponse is used by authenticators to respond to Relying Party requests.
// https://www.w3.org/TR/webauthn/#authenticatorresponse
type AuthenticatorResponse struct {
	// This attribute contains a JSON serialization of the client data passed to the authenticator by the client in
	// its call to either create() or get().
	ClientDataJSON []byte `json:"clientDataJSON"`
}

// ParsedAuthenticatorResponse is a parsed version of AuthenticatorResponse.
// https://www.w3.org/TR/webauthn/#authenticatorresponse
type ParsedAuthenticatorResponse struct {
	// This attribute contains the parsed client data passed to the authenticator by the client in its call to either
	// create() or get().
	ClientData CollectedClientData
}

// CollectedClientData represents the contextual bindings of both the WebAuthn Relying Party and the client. It is a
// key-value mapping whose keys are strings. Values can be any type that has a valid encoding in JSON. Its
// structure is defined by the following Web IDL.
// https://www.w3.org/TR/webauthn/#client-data
type CollectedClientData struct {
	// This member contains the string "webauthn.create" when creating new credentials, and "webauthn.get" when getting
	// an assertion from an existing credential. The purpose of this member is to prevent certain types of signature
	// confusion attacks (where an attacker substitutes one legitimate signature for another).
	Type string `json:"type"`
	// This member contains the base64url encoding of the challenge provided by the RP. See the §13.1 Cryptographic
	// Challenges security consideration.
	Challenge string `json:"challenge"`
	// This member contains the fully qualified origin of the requester, as provided to the authenticator by the client,
	// in the syntax defined by [RFC6454].
	Origin string `json:"origin"`
	// This OPTIONAL member contains information about the state of the Token Binding protocol used when communicating
	// with the Relying Party. Its absence indicates that the client doesn’t support token binding.
	TokenBinding *TokenBinding `json:"tokenBinding,omitempty"`
}

// TokenBinding represents the token binding.
// https://www.w3.org/TR/webauthn/#dictdef-tokenbinding
type TokenBinding struct {
	// This member is one of the following:
	Status TokenBindingStatus `json:"status,omitempty"`
	// This member MUST be present if status is present, and MUST a base64url encoding of the Token Binding ID that was
	// used when communicating with the Relying Party.
	ID string `json:"id,omitempty"`
}

// TokenBindingStatus represents the status of a TokenBinding.
// https://www.w3.org/TR/webauthn/#enumdef-tokenbindingstatus
type TokenBindingStatus string

const (
	// TokenBindingStatusPresent indicates the client supports token binding, but it was not negotiated when
	// communicating with the Relying Party.
	TokenBindingStatusPresent TokenBindingStatus = "present"
	// TokenBindingStatusSupported indicates token binding was used when communicating with the Relying Party. In this
	// case, the id member MUST be present.
	TokenBindingStatusSupported = "supported"
)

// IsValid checks whether the CollectedClientData is valid. If originalChallenge is nil, the challenge value
// will not be checked (INSECURE). If relyingPartyOrigin is empty, the relying party will not be checked (INSEUCRE).
// If the data is invalid, an error is returned, usually of the type Error.
func (c CollectedClientData) IsValid(requiredType string, originalChallenge []byte, relyingPartyOrigin string) error {
	// Verify that the value of C.type is requiredType
	if c.Type != requiredType {
		return ErrInvalidType.WithDebugf("%q did not match required %q", c.Type, requiredType)
	}

	if originalChallenge != nil {
		// Verify that the value of C.challenge matches the challenge that was sent to the authenticator in the
		// create()/get() call
		challenge, err := base64.RawURLEncoding.DecodeString(c.Challenge) // This is raw URL encoding, so the JSON parser does not handle it
		if err != nil {
			return ErrInvalidChallenge.WithDebug(err.Error())
		}
		if !bytes.Equal(challenge, originalChallenge) {
			return ErrInvalidChallenge
		}
	}

	// Verify that the value of C.origin matches the Relying Party's origin.
	if relyingPartyOrigin != "" && c.Origin != relyingPartyOrigin {
		return ErrInvalidOrigin.WithDebugf("%q did not match required %q", relyingPartyOrigin, c.Origin)
	}

	// TODO: Verify that the value of C.tokenBinding.status matches the state of Token Binding for the TLS connection
	// over which the assertion was obtained. If Token Binding was used on that TLS connection, also verify that
	// C.tokenBinding.id matches the base64url encoding of the Token Binding ID for the connection.

	return nil
}

// AuthenticatorData encodes contextual bindings made by the authenticator. These bindings are controlled
// by the authenticator itself, and derive their trust from the WebAuthn Relying Party's assessment of the security
// properties of the authenticator. In one extreme case, the authenticator may be embedded in the client, and its
// bindings may be no more trustworthy than the client data. At the other extreme, the authenticator may be a discrete
// entity with high-security hardware and software, connected to the client over a secure channel. In both cases, the
// Relying Party receives the authenticator data in the same format, and uses its knowledge of the authenticator to
// make trust decisions.
type AuthenticatorData struct {
	// SHA-256 hash of the RP ID associated with the credential.
	RPIDHash []byte
	// Flags
	Flags AuthenticatorDataFlags
	// Signature counter, 32-bit unsigned big-endian integer.
	SignCount uint32
	// attested credential data (if present). See §6.4.1 Attested credential data for details. Its length depends on the
	// length of the credential ID and credential public key being attested.
	AttestedCredentialData AttestedCredentialData
	// Raw contains the raw bytes of this AuthenticatorData.
	Raw []byte
}

// IsValid checks whether the AuthenticatorData is valid. If relyingPartyID is empty, the relying party will not be
// checked (INSEUCRE). If the data is invalid, an error is returned, usually of the type Error.
func (a AuthenticatorData) IsValid(relyingPartyID string) error {
	// Verify that the RP ID hash in authData is indeed the SHA-256 hash of the RP ID expected by the RP
	rpHash := sha256.Sum256([]byte(relyingPartyID))
	if relyingPartyID != "" && !bytes.Equal(rpHash[:], a.RPIDHash) {
		return ErrInvalidOrigin.WithDebugf("hash %X did not match required %X", a.RPIDHash, rpHash[:])
	}

	// Verify that the User Present bit of the flags in authData is set
	if !a.Flags.UserPresent() {
		return ErrNoUserPresent
	}

	return nil
}

var _ encoding.BinaryUnmarshaler = (*AuthenticatorData)(nil)
var _ encoding.BinaryMarshaler = (*AuthenticatorData)(nil)

// UnmarshalBinary implements the encoding.BinaryUnmarshaler interface.
func (a *AuthenticatorData) UnmarshalBinary(authData []byte) error {
	if len(authData) < 37 {
		return ErrInvalidRequest.WithDebug("invalid authenticator data")
	}

	a.RPIDHash = authData[0:32]
	a.Flags = AuthenticatorDataFlags(authData[32])
	a.SignCount = binary.BigEndian.Uint32(authData[33:37])

	if a.Flags.HasAttestedCredentialData() && len(authData) > 37 {
		a.AttestedCredentialData.AAGUID = authData[37:53]
		credentialIDLength := binary.BigEndian.Uint16(authData[53:55])

		a.AttestedCredentialData.CredentialID = authData[55 : 55+credentialIDLength]

		var err error
		a.AttestedCredentialData.COSEKey, err = cose.ParseCOSE(authData[55+credentialIDLength:])
		if err != nil {
			return ErrInvalidRequest.WithDebugf("unable to parse COSE key: %v", err.Error())
		}
	}

	a.Raw = authData

	return nil
}

// MarshalBinary implements the encoding.BinaryMarshaler interface.
func (a *AuthenticatorData) MarshalBinary() ([]byte, error) {
	return nil, fmt.Errorf("unsupported operation")
}

// AuthenticatorDataFlags are the flags that are present in the authenticator data.
type AuthenticatorDataFlags byte

const (
	// AuthenticatorDataFlagUserPresent indicates the UP flag.
	AuthenticatorDataFlagUserPresent = 0x001 // 0000 0001
	// AuthenticatorDataFlagUserVerified indicates the UV flag.
	AuthenticatorDataFlagUserVerified = 0x002 // 0000 0010
	// AuthenticatorDataFlagHasCredentialData indicates the AT flag.
	AuthenticatorDataFlagHasCredentialData = 0x040 // 0100 0000
	// AuthenticatorDataFlagHasExtension indicates the ED flag.
	AuthenticatorDataFlagHasExtension = 0x080 // 1000 0000
)

// UserPresent returns whether the UP flag is set.
func (f AuthenticatorDataFlags) UserPresent() bool {
	return (f & AuthenticatorDataFlagUserPresent) == AuthenticatorDataFlagUserPresent
}

// UserVerified returns whether the UV flag is set.
func (f AuthenticatorDataFlags) UserVerified() bool {
	return (f & AuthenticatorDataFlagUserVerified) == AuthenticatorDataFlagUserVerified
}

// HasAttestedCredentialData returns whether the AT flag is set.
func (f AuthenticatorDataFlags) HasAttestedCredentialData() bool {
	return (f & AuthenticatorDataFlagHasCredentialData) == AuthenticatorDataFlagHasCredentialData
}

// HasExtensions returns whether the ED flag is set.
func (f AuthenticatorDataFlags) HasExtensions() bool {
	return (f & AuthenticatorDataFlagHasExtension) == AuthenticatorDataFlagHasExtension
}

// AttestedCredentialData represents the AttestedCredentialData type in the WebAuthn specification.
// https://www.w3.org/TR/webauthn/#attested-credential-data
type AttestedCredentialData struct {
	// The AAGUID of the authenticator.
	AAGUID []byte
	// A probabilistically-unique byte sequence identifying a public key credential source and its authentication
	// assertions.
	CredentialID []byte
	// The decoded credential public key.
	COSEKey interface{}
}
