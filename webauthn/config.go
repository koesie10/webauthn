package webauthn

import "fmt"

var defaultSessionKeyPrefixChallenge = "webauthn.challenge"
var defaultSessionKeyPrefixUserID = "webauthn.user.id"

// Config holds all the configuration for WebAuthn
type Config struct {
	// RelyingPartyName is a human-palatable identifier for the Relying Party, intended only for display. For example,
	// "ACME Corporation", "Wonderful Widgets, Inc." or "ОАО Примертех".
	RelyingPartyName string
	// RelyingPartyID is a unique identifier for the Relying Party entity. It must be a valid domain string that
	// identifies the Relying Party on whose behalf a registration or login is being performed. A public key credential
	// can only be used for authentication with the same RP ID it was registered with.
	// By default, it is set to the caller's origin effective domain. It may be overridden, as long as the RP ID is
	// a registrable domain suffix or is equal to the caller's effective domain.
	// For example, given a Relying Party whose origin is https://login.example.com:1337, then the following RP IDs
	// are valid: login.example.com (default) and example.com, but not m.login.example.com and not com.
	// In production, this value should be set. If it is not set, the implementation is INSECURE and the RP ID hash
	// supplied by the authenticator will not be checked.
	RelyingPartyID string
	// RelyingPartyOrigin is the RP origin that an authenticator response will be compared with. If it is empty,
	// the value will be ignored. However, this is INSECURE and should not be used in production.
	// For example, given a Relying Party whose origin is https://login.example.com:1337, this value should be set
	// to "https://login.example.com:1337".
	RelyingPartyOrigin string

	// AuthenticatorStore will be used to store authenticators of a user.
	AuthenticatorStore AuthenticatorStore

	// SessionKeyPrefixChallenge holds the prefix of the key of the challenge in the session. If it is not set, it will
	// be set to "webauthn.challenge".
	SessionKeyPrefixChallenge string
	// SessionKeyPrefixUserID holds the prefix of the key of the user ID in the session. If it is not set, it will be
	// set to "webauthn.user.id".
	SessionKeyPrefixUserID string

	// Timeout is the amount of time in milliseconds the user will be permitted to authenticate with their device on
	// registration and login. The default is 30000, i.e. 30 seconds.
	Timeout uint

	// Debug sets a few settings related to ease of debugging, such as sharing more error information to clients.
	Debug bool
}

// Validate validates that all required fields in Config are set.
func (c *Config) Validate() error {
	if c.RelyingPartyName == "" {
		return fmt.Errorf("missing RelyingPartyName")
	}

	if c.AuthenticatorStore == nil {
		return fmt.Errorf("missing AuthenticatorStore")
	}

	if c.SessionKeyPrefixChallenge == "" {
		c.SessionKeyPrefixChallenge = defaultSessionKeyPrefixChallenge
	}
	if c.SessionKeyPrefixUserID == "" {
		c.SessionKeyPrefixUserID = defaultSessionKeyPrefixUserID
	}
	if c.Timeout == 0 {
		c.Timeout = 30000
	}

	return nil
}
