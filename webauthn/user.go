package webauthn

// User should be implemented by users used in the request handlers.
type User interface {
	// WebAuthID should return the ID of the user. This could for example be the binary encoding of an int.
	WebAuthID() []byte
	// WebAuthName should return the name of the user.
	WebAuthName() string
	// WebAuthDisplayName should return the display name of the user.
	WebAuthDisplayName() string
}

// Authenticator represents an authenticator that can be used by a user.
type Authenticator interface {
	WebAuthID() []byte
	WebAuthCredentialID() []byte
	WebAuthPublicKey() []byte
	WebAuthAAGUID() []byte
	WebAuthSignCount() uint32
}

// AuthenticatorStore should be implemented by the storage layer to store authenticators.
type AuthenticatorStore interface {
	// AddAuthenticator should add the given authenticator to a user. The authenticator's type should not be depended
	// on; it is constructed by this package. All information should be stored in a way such that it is retrievable
	// in the future using GetAuthenticator and GetAuthenticators.
	AddAuthenticator(user User, authenticator Authenticator) error
	// GetAuthenticator gets a single Authenticator by the given id, as returned by Authenticator.WebAuthID.
	GetAuthenticator(id []byte) (Authenticator, error)
	// GetAuthenticators gets a list of all registered authenticators for this user. It might be the case that the user
	// has been constructed by this package and the only non-empty value is the WebAuthID. In this case, the store
	// should still return the authenticators as specified by the ID.
	GetAuthenticators(user User) ([]Authenticator, error)
}

type defaultUser struct {
	id []byte
}

var _ User = (*defaultUser)(nil)

func (u *defaultUser) WebAuthID() []byte {
	return u.id
}

func (u *defaultUser) WebAuthName() string {
	return "default"
}

func (u *defaultUser) WebAuthDisplayName() string {
	return "default"
}

type defaultAuthenticator struct {
	id           []byte
	credentialID []byte
	publicKey    []byte
	aaguid       []byte
	signCount    uint32
}

var _ Authenticator = (*defaultAuthenticator)(nil)

func (a *defaultAuthenticator) WebAuthID() []byte {
	return a.id
}

func (a *defaultAuthenticator) WebAuthCredentialID() []byte {
	return a.credentialID
}

func (a *defaultAuthenticator) WebAuthPublicKey() []byte {
	return a.publicKey
}

func (a *defaultAuthenticator) WebAuthAAGUID() []byte {
	return a.aaguid
}

func (a *defaultAuthenticator) WebAuthSignCount() uint32 {
	return a.signCount
}
