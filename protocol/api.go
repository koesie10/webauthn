package protocol

// CredentialCreationOptions contains the options that should be passed to navigator.credentials.create().
// https://www.w3.org/TR/webauthn/#credentialcreationoptions-extension
type CredentialCreationOptions struct {
	PublicKey PublicKeyCredentialCreationOptions `json:"publicKey"`
}

// CredentialRequestOptions contains the options that should be passed to navigator.credentials.get().
// https://www.w3.org/TR/webauthn/#credentialrequestoptions-extension
type CredentialRequestOptions struct {
	PublicKey PublicKeyCredentialRequestOptions `json:"publicKey"`
}

// The PublicKeyCredentialCreationOptions dictionary supplies create() with the data it needs to generate an attestation.
// https://www.w3.org/TR/webauthn/#dictdef-publickeycredentialcreationoptions
type PublicKeyCredentialCreationOptions struct {
	// This member contains data about the Relying Party responsible for the request.
	// Its value’s name member is REQUIRED. See §5.4.1 Public Key Entity Description (dictionary
	// PublicKeyCredentialEntity) for further details.
	// Its value’s id member specifies the RP ID with which the credential should be associated. If omitted, its value
	// will be the CredentialsContainer object’s relevant settings object's origin's effective domain. See §5.4.2
	// Relying Party Parameters for Credential Generation (dictionary PublicKeyCredentialRpEntity) for further details.
	RP PublicKeyCredentialRpEntity `json:"rp"`
	// This member contains data about the user account for which the Relying Party is requesting attestation.
	// Its value’s name, displayName and id members are REQUIRED. See §5.4.1 Public Key Entity Description
	// (dictionary PublicKeyCredentialEntity) and §5.4.3 User Account Parameters for Credential Generation
	// (dictionary PublicKeyCredentialUserEntity) for further details.
	User PublicKeyCredentialUserEntity `json:"user"`

	// This member contains a challenge intended to be used for generating the newly created credential’s attestation
	// object. See the §13.1 Cryptographic Challenges security consideration.
	Challenge Challenge `json:"challenge"`
	// This member contains information about the desired properties of the credential to be created. The sequence is
	// ordered from most preferred to least preferred. The client makes a best-effort to create the most preferred
	// credential that it can.
	PubKeyCredParams []PublicKeyCredentialParameters `json:"pubKeyCredParams,omitempty"`

	// This member specifies a time, in milliseconds, that the caller is willing to wait for the call to complete.
	// This is treated as a hint, and MAY be overridden by the client.
	Timeout uint `json:"timeout,omitempty"`
	// This member is intended for use by Relying Parties that wish to limit the creation of multiple credentials for
	// the same account on a single authenticator. The client is requested to return an error if the new credential
	// would be created on an authenticator that also contains one of the credentials enumerated in this parameter.
	ExcludeCredentials []PublicKeyCredentialDescriptor `json:"excludeCredentials,omitempty"`
	// This member is intended for use by Relying Parties that wish to select the appropriate authenticators to
	// participate in the create() operation.
	AuthenticatorSelection AuthenticatorSelectionCriteria `json:"authenticatorSelection,omitempty"`
	// This member is intended for use by Relying Parties that wish to express their preference for attestation
	// conveyance. The default is none.
	Attestation AttestationConveyancePreference `json:"attestation,omitempty"`
	// This member contains additional parameters requesting additional processing by the client and authenticator. For
	// example, the caller may request that only authenticators with certain capabilities be used to create the
	// credential, or that particular information be returned in the attestation object. Some extensions are defined in
	// §9 WebAuthn Extensions; consult the IANA "WebAuthn Extension Identifier" registry established by
	// [WebAuthn-Registries] for an up-to-date list of registered WebAuthn Extensions.
	Extensions AuthenticationExtensionsClientInputs `json:"extensions,omitempty"`
}

// The PublicKeyCredentialRequestOptions dictionary supplies get() with the data it needs to generate an assertion. Its
// challenge member MUST be present, while its other members are OPTIONAL.
// https://www.w3.org/TR/webauthn/#dictdef-publickeycredentialrequestoptions
type PublicKeyCredentialRequestOptions struct {
	// This member represents a challenge that the selected authenticator signs, along with other data, when producing
	// an authentication assertion. See the §13.1 Cryptographic Challenges security consideration.
	Challenge Challenge `json:"challenge"`
	// This OPTIONAL member specifies a time, in milliseconds, that the caller is willing to wait for the call to
	// complete. The value is treated as a hint, and MAY be overridden by the client.
	Timeout uint `json:"timeout,omitempty"`
	// This OPTIONAL member specifies the relying party identifier claimed by the caller. If omitted, its value will be
	// the CredentialsContainer object’s relevant settings object's origin's effective domain.
	RPID string `json:"rpId,omitempty"`
	// This OPTIONAL member contains a list of PublicKeyCredentialDescriptor objects representing public key credentials
	// acceptable to the caller, in descending order of the caller’s preference (the first item in the list is the most
	// preferred credential, and so on down the list).
	AllowCredentials []PublicKeyCredentialDescriptor `json:"allowCredentials,omitempty"`
	// This member describes the Relying Party's requirements regarding user verification for the get() operation.
	// Eligible authenticators are filtered to only those capable of satisfying this requirement.
	UserVerification UserVerificationRequirement `json:"userVerification,omitempty"`
	// This OPTIONAL member contains additional parameters requesting additional processing by the client and
	// authenticator. For example, if transaction confirmation is sought from the user, then the prompt string might
	// be included as an extension.
	Extensions AuthenticationExtensionsClientInputs `json:"extensions,omitempty"`
}

// The PublicKeyCredentialRpEntity dictionary is used to supply additional Relying Party attributes when creating a
// new credential.
// https://www.w3.org/TR/webauthn/#dictdef-publickeycredentialrpentity
type PublicKeyCredentialRpEntity struct {
	PublicKeyCredentialEntity
	// A unique identifier for the Relying Party entity, which sets the RP ID.
	ID string `json:"id,omitempty"`
}

// The PublicKeyCredentialEntity dictionary describes a user account, or a WebAuthn Relying Party, with which a
// public key credential is associated.
// https://www.w3.org/TR/webauthn/#dictdef-publickeycredentialentity
type PublicKeyCredentialEntity struct {
	// A human-palatable name for the entity. Its function depends on what the PublicKeyCredentialEntity represents.
	Name string `json:"name"`
}

// The PublicKeyCredentialUserEntity dictionary is used to supply additional user account attributes when creating a
// new credential.
// https://www.w3.org/TR/webauthn/#dictdef-publickeycredentialuserentity
type PublicKeyCredentialUserEntity struct {
	PublicKeyCredentialEntity

	// The user handle of the user account entity. To ensure secure operation, authentication and authorization
	// decisions MUST be made on the basis of this id member, not the displayName nor name members. See
	// Section 6.1 of [RFC8266].
	ID []byte `json:"id"`
	// A human-palatable name for the user account, intended only for display. For example, "Alex P. Müller" or
	// "田中 倫". The Relying Party SHOULD let the user choose this, and SHOULD NOT restrict the choice more than
	// necessary.
	DisplayName string `json:"displayName"`
}

// PublicKeyCredentialType defines the valid credential types. It is an extension point; values can be added to it in the
// future, as more credential types are defined. The values of this enumeration are used for versioning the
// Authentication Assertion and attestation structures according to the type of the authenticator.
// Currently one credential type is defined, namely "public-key".
// https://www.w3.org/TR/webauthn/#enumdef-publickeycredentialtype
type PublicKeyCredentialType string

const (
	// PublicKeyCredentialTypePublicKey is the only credential type defined, namely "public-key".
	PublicKeyCredentialTypePublicKey PublicKeyCredentialType = "public-key"
)

// A COSEAlgorithmIdentifier's value is a number identifying a cryptographic algorithm. The algorithm identifiers
// SHOULD be values registered in the IANA COSE Algorithms registry [IANA-COSE-ALGS-REG], for instance, -7 for
// "ES256" and -257 for "RS256".
// https://www.w3.org/TR/webauthn/#alg-identifier
type COSEAlgorithmIdentifier int

const (
	// ES256 is the COSE Algorithm Identifier of ECDSA 256
	ES256 COSEAlgorithmIdentifier = -7
	// RS256 is the COSE Algorithm Identifier of RSA 256
	RS256 COSEAlgorithmIdentifier = -257
)

// AuthenticatorTransport represents the transport used by an authenticator. Authenticators may implement various
// transports for communicating with clients. This enumeration defines hints as to
// how clients might communicate with a particular authenticator in order to obtain an assertion for a specific
// credential. Note that these hints represent the WebAuthn Relying Party's best belief as to how an authenticator may
// be reached. A Relying Party may obtain a list of transports hints from some attestation statement formats or via
// some out-of-band mechanism; it is outside the scope of this specification to define that mechanism.
// https://www.w3.org/TR/webauthn/#enumdef-authenticatortransport
type AuthenticatorTransport string

const (
	// AuthenticatorTransportUSB indicates the respective authenticator can be contacted over removable USB.
	AuthenticatorTransportUSB AuthenticatorTransport = "usb"
	// AuthenticatorTransportNFC indicates the respective authenticator can be contacted over Near Field Communication (NFC).
	AuthenticatorTransportNFC = "nfc"
	// AuthenticatorTransportBLE indicates the respective authenticator can be contacted over Bluetooth Smart (Bluetooth Low Energy / BLE).
	AuthenticatorTransportBLE = "ble"
	// AuthenticatorTransportInternal indicates the respective authenticator is contacted using a client device-specific transport. These
	// authenticators are not removable from the client device.
	AuthenticatorTransportInternal = "internal"
)

// PublicKeyCredentialParameters is used to supply additional parameters when creating a new credential.
// https://www.w3.org/TR/webauthn/#dictdef-publickeycredentialparameters
type PublicKeyCredentialParameters struct {
	// This member specifies the type of credential to be created.
	Type PublicKeyCredentialType `json:"type"`
	// This member specifies the cryptographic signature algorithm with which the newly generated credential will be
	// used, and thus also the type of asymmetric key pair to be generated, e.g., RSA or Elliptic Curve.
	Algorithm COSEAlgorithmIdentifier `json:"alg"`
}

// PublicKeyCredentialDescriptor contains the attributes that are specified by a caller when referring to a public key credential as
// an input parameter to the create() or get() methods. It mirrors the fields of the PublicKeyCredential object
// returned by the latter methods.
// https://www.w3.org/TR/webauthn/#credential-dictionary
type PublicKeyCredentialDescriptor struct {
	// This member contains the type of the public key credential the caller is referring to.
	Type PublicKeyCredentialType `json:"type"`
	// This member contains the credential ID of the public key credential the caller is referring to.
	ID []byte `json:"id"`
	// This OPTIONAL member contains a hint as to how the client might communicate with the managing authenticator of
	// the public key credential the caller is referring to.
	Transport []AuthenticatorTransport `json:"transports,omitempty"`
}

// The AuthenticatorSelectionCriteria may be used by WebAuthn Relying Parties to specify their requirements
// regarding authenticator attributes.
// https://www.w3.org/TR/webauthn/#dictdef-authenticatorselectioncriteria
type AuthenticatorSelectionCriteria struct {
	// If this member is present, eligible authenticators are filtered to only authenticators attached with the
	// specified §5.4.5 Authenticator Attachment enumeration (enum AuthenticatorAttachment).
	AuthenticatorAttachment AuthenticatorAttachment `json:"authenticatorAttachment,omitempty"`
	// This member describes the Relying Parties' requirements regarding resident credentials. If the parameter is set
	// to true, the authenticator MUST create a client-side-resident public key credential source when creating a
	// public key credential.
	RequireResidentKey bool `json:"requireResidentKey"`
	// This member describes the Relying Party's requirements regarding user verification for the create() operation.
	// Eligible authenticators are filtered to only those capable of satisfying this requirement.
	UserVerification UserVerificationRequirement `json:"userVerification,omitempty"`
}

// AuthenticatorAttachment's values describe authenticators' attachment modalities. Relying Parties use this for two purposes:
// to express a preferred authenticator attachment modality when calling navigator.credentials.create() to create a
// credential, and
// to inform the client of the Relying Party's best belief about how to locate the managing authenticators of the
// credentials listed in allowCredentials when calling navigator.credentials.get().
// https://www.w3.org/TR/webauthn/#enumdef-authenticatorattachment
type AuthenticatorAttachment string

const (
	// AuthenticatorAttachmentPlatform indicates platform attachment.
	AuthenticatorAttachmentPlatform AuthenticatorAttachment = "platform"
	// AuthenticatorAttachmentCrossPlatform indicates cross-platform attachment.
	AuthenticatorAttachmentCrossPlatform = "cross-platform"
)

// UserVerificationRequirement may be used by a WebAuthn Relying Party to require user verification for some of its
// operations but not for others.
// https://www.w3.org/TR/webauthn/#enumdef-userverificationrequirement
type UserVerificationRequirement string

const (
	// UserVerificationRequired indicates that the Relying Party requires user verification for the operation and will fail the
	// operation if the response does not have the UV flag set.
	UserVerificationRequired UserVerificationRequirement = "required"
	// UserVerificationPreferred indicates that the Relying Party prefers user verification for the operation if possible, but
	// will not fail the operation if the response does not have the UV flag set.
	UserVerificationPreferred = "preferred"
	// UserVerificationDiscouraged indicates that the Relying Party does not want user verification employed during the operation
	// (e.g., in the interest of minimizing disruption to the user interaction flow).
	UserVerificationDiscouraged = "discouraged"
)

// AttestationConveyancePreference may be used by WebAuthn Relying Parties to specify their preference regarding attestation
// conveyance during credential generation.
// https://www.w3.org/TR/webauthn/#enumdef-attestationconveyancepreference
type AttestationConveyancePreference string

const (
	// AttestationConveyancePreferenceNone indicates that the Relying Party is not interested in authenticator attestation. For example, in
	// order to potentially avoid having to obtain user consent to relay identifying information to the Relying Party,
	// or to save a roundtrip to an Attestation CA. This is the default value.
	AttestationConveyancePreferenceNone = "none"
	// AttestationConveyancePreferenceIndirect indicates that the Relying Party prefers an attestation conveyance yielding verifiable attestation
	// statements, but allows the client to decide how to obtain such attestation statements. The client MAY replace
	// the authenticator-generated attestation statements with attestation statements generated by an Anonymization CA,
	// in order to protect the user’s privacy, or to assist Relying Parties with attestation verification in a
	// heterogeneous ecosystem.
	AttestationConveyancePreferenceIndirect = "indirect"
	// AttestationConveyancePreferenceDirect indicates that the Relying Party wants to receive the attestation statement as generated by the
	// authenticator.
	AttestationConveyancePreferenceDirect = "direct"
)

// AuthenticationExtensionsClientInputs contains the client extension input values for zero or more WebAuthn extensions, as defined
// in §9 WebAuthn Extensions.
// https://www.w3.org/TR/webauthn/#dictdef-authenticationextensionsclientinputs
type AuthenticationExtensionsClientInputs map[string]interface{}
