package webauthn

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"

	"github.com/koesie10/webauthn/protocol"
)

// GetLoginOptions will return the options that need to be passed to navigator.credentials.get(). This should
// be returned to the user via e.g. JSON over HTTP. For convenience, use StartLogin.
func (w *WebAuthn) GetLoginOptions(user User, session Session) (*protocol.CredentialRequestOptions, error) {
	chal, err := protocol.NewChallenge()
	if err != nil {
		return nil, err
	}

	options := &protocol.CredentialRequestOptions{
		PublicKey: protocol.PublicKeyCredentialRequestOptions{
			Challenge: chal,
			Timeout:   w.Config.Timeout,
		},
	}

	if user != nil {
		authenticators, err := w.Config.AuthenticatorStore.GetAuthenticators(user)
		if err != nil {
			return nil, err
		}

		allowCredentials := make([]protocol.PublicKeyCredentialDescriptor, len(authenticators))

		for i, authr := range authenticators {
			allowCredentials[i] = protocol.PublicKeyCredentialDescriptor{
				ID:   authr.WebAuthCredentialID(),
				Type: protocol.PublicKeyCredentialTypePublicKey,
			}
		}

		options.PublicKey.AllowCredentials = allowCredentials
	}

	if err := session.Set(w.Config.SessionKeyPrefixChallenge+".login", []byte(chal)); err != nil {
		return nil, err
	}

	return options, nil
}

// StartLogin is a HTTP request handler which writes the options to be passed to navigator.credentials.get()
// to the http.ResponseWriter. The user argument is optional and can be nil, in which case the allowCredentials
// option will not be set and AuthenticatorStore.GetAuthenticators will not be called.
func (w *WebAuthn) StartLogin(r *http.Request, rw http.ResponseWriter, user User, session Session) {
	options, err := w.GetLoginOptions(user, session)
	if err != nil {
		w.writeError(r, rw, err)
		return
	}

	w.write(r, rw, options)
}

// ParseAndFinishLogin should receive the response of navigator.credentials.get(). If
// user is non-nil, it will be checked that the authenticator is owned by that user. If the request is valid,
// the authenticator will be returned. For convenience, use FinishLogin.
func (w *WebAuthn) ParseAndFinishLogin(assertionResponse protocol.AssertionResponse, user User, session Session) (Authenticator, error) {
	rawChal, err := session.Get(w.Config.SessionKeyPrefixChallenge + ".login")
	if err != nil {
		return nil, protocol.ErrInvalidRequest.WithDebug("missing challenge in session")
	}
	chal, ok := rawChal.([]byte)
	if !ok {
		return nil, protocol.ErrInvalidRequest.WithDebug("invalid challenge session value")
	}

	if err := session.Delete(w.Config.SessionKeyPrefixChallenge + ".login"); err != nil {
		return nil, err
	}

	p, err := protocol.ParseAssertionResponse(assertionResponse)
	if err != nil {
		return nil, err
	}

	// 1. If the allowCredentials option was given when this authentication ceremony was initiated, verify that
	// credential.id identifies one of the public key credentials that were listed in allowCredentials.
	if user != nil {
		authenticators, err := w.Config.AuthenticatorStore.GetAuthenticators(user)
		if err != nil {
			return nil, err
		}

		var authrFound bool
		for _, authr := range authenticators {
			if bytes.Equal(authr.WebAuthID(), p.RawID) {
				authrFound = true
				break
			}
		}

		if !authrFound {
			return nil, protocol.ErrInvalidRequest.WithDebug("authenticator is not owned by user")
		}
	}

	// 2. If credential.response.userHandle is present, verify that the user identified by this value is the owner of
	// the public key credential identified by credential.id.
	if p.Response.UserHandle != nil && len(p.Response.UserHandle) > 0 {
		if user != nil {
			if !bytes.Equal(p.Response.UserHandle, user.WebAuthID()) {
				return nil, protocol.ErrInvalidRequest.WithDebug("authenticator's user handle does not equal user ID")
			}
		} else {
			authenticators, err := w.Config.AuthenticatorStore.GetAuthenticators(&defaultUser{id: p.Response.UserHandle})
			if err != nil {
				return nil, err
			}

			var authrFound bool
			for _, authr := range authenticators {
				if bytes.Equal(authr.WebAuthID(), p.RawID) {
					authrFound = true
					break
				}
			}

			if !authrFound {
				return nil, protocol.ErrInvalidRequest.WithDebug("authenticator is not owned by user")
			}
		}
	}

	// Using credential’s id attribute (or the corresponding rawId, if base64url encoding is inappropriate for your use
	// case), look up the corresponding credential public key.
	authr, err := w.Config.AuthenticatorStore.GetAuthenticator(p.RawID)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(authr.WebAuthPublicKey())
	if block == nil {
		return nil, fmt.Errorf("invalid stored public key, unable to decode")
	}

	cert, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	valid, err := protocol.IsValidAssertion(p, chal, w.Config.RelyingPartyID, w.Config.RelyingPartyOrigin, &x509.Certificate{
		PublicKey: cert,
	})
	if err != nil {
		return nil, err
	}

	if !valid {
		return nil, protocol.ErrInvalidRequest.WithDebug("invalid login")
	}

	return authr, nil
}

// FinishLogin is a HTTP request handler which should receive the response of navigator.credentials.get(). If
// user is non-nil, it will be checked that the authenticator is owned by that user. If the request is valid,
// the authenticator will be returned and nothing will have been written to http.ResponseWriter. If authenticator is
// nil, an error has been written to http.ResponseWriter and should be returned as-is.
func (w *WebAuthn) FinishLogin(r *http.Request, rw http.ResponseWriter, user User, session Session) Authenticator {
	var assertionResponse protocol.AssertionResponse

	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(&assertionResponse); err != nil {
		w.writeError(r, rw, protocol.ErrInvalidRequest.WithDebug(err.Error()))
		return nil
	}

	authr, err := w.ParseAndFinishLogin(assertionResponse, user, session)
	if err != nil {
		w.writeError(r, rw, err)
		return nil
	}

	return authr
}
