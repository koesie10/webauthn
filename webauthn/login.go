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

// StartLogin is a HTTP request handler which writes the options to be passed to navigator.credentials.get()
// to the http.ResponseWriter. The user argument is optional and can be nil, in which case the allowCredentials
// option will not be set and AuthenticatorStore.GetAuthenticators will not be called.
func (w *WebAuthn) StartLogin(r *http.Request, rw http.ResponseWriter, user User, session Session) {
	chal, err := protocol.NewChallenge()
	if err != nil {
		w.writeError(r, rw, err)
		return
	}

	options := protocol.CredentialRequestOptions{
		PublicKey: protocol.PublicKeyCredentialRequestOptions{
			Challenge: chal,
			Timeout:   w.Config.Timeout,
		},
	}

	if user != nil {
		authenticators, err := w.Config.AuthenticatorStore.GetAuthenticators(user)
		if err != nil {
			w.writeError(r, rw, err)
			return
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
		w.writeError(r, rw, err)
		return
	}

	w.write(r, rw, options)
}

// FinishLogin is a HTTP request handler which should receive the response of navigator.credentials.get(). If
// user is non-nil, it will be checked that the authenticator is owned by that user. If the request is valid,
// the authenticator will be returned and nothing will have been written to http.ResponseWriter. If authenticator is
// nil, an error has been written to http.ResponseWriter and should be returned as-is.
func (w *WebAuthn) FinishLogin(r *http.Request, rw http.ResponseWriter, user User, session Session) Authenticator {
	rawChal, err := session.Get(w.Config.SessionKeyPrefixChallenge + ".login")
	if err != nil {
		w.writeErrorCode(r, rw, http.StatusBadRequest, err)
		return nil
	}
	chal, ok := rawChal.([]byte)
	if !ok {
		w.writeError(r, rw, protocol.ErrInvalidRequest.WithDebug("invalid challenge session value"))
		return nil
	}

	if err := session.Delete(w.Config.SessionKeyPrefixChallenge + ".login"); err != nil {
		w.writeError(r, rw, err)
		return nil
	}

	var assertionResponse protocol.AssertionResponse

	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(&assertionResponse); err != nil {
		w.writeError(r, rw, protocol.ErrInvalidRequest.WithDebug(err.Error()))
		return nil
	}

	p, err := protocol.ParseAssertionResponse(assertionResponse)
	if err != nil {
		w.writeError(r, rw, err)
		return nil
	}

	// 1. If the allowCredentials option was given when this authentication ceremony was initiated, verify that
	// credential.id identifies one of the public key credentials that were listed in allowCredentials.
	if user != nil {
		authenticators, err := w.Config.AuthenticatorStore.GetAuthenticators(user)
		if err != nil {
			w.writeError(r, rw, err)
			return nil
		}

		var authrFound bool
		for _, authr := range authenticators {
			if bytes.Equal(authr.WebAuthID(), p.RawID) {
				authrFound = true
				break
			}
		}

		if !authrFound {
			w.writeError(r, rw, protocol.ErrInvalidRequest.WithDebug("authenticator is not owned by user"))
		}
	}

	// 2. If credential.response.userHandle is present, verify that the user identified by this value is the owner of
	// the public key credential identified by credential.id.
	if p.Response.UserHandle != nil && len(p.Response.UserHandle) > 0 {
		if user != nil {
			if !bytes.Equal(p.Response.UserHandle, user.WebAuthID()) {
				w.writeError(r, rw, protocol.ErrInvalidRequest.WithDebug("authenticator's user handle does not equal user ID"))
				return nil
			}
		} else {
			authenticators, err := w.Config.AuthenticatorStore.GetAuthenticators(&defaultUser{id: p.Response.UserHandle})
			if err != nil {
				w.writeError(r, rw, err)
				return nil
			}

			var authrFound bool
			for _, authr := range authenticators {
				if bytes.Equal(authr.WebAuthID(), p.RawID) {
					authrFound = true
					break
				}
			}

			if !authrFound {
				w.writeError(r, rw, protocol.ErrInvalidRequest.WithDebug("authenticator is not owned by user"))
				return nil
			}
		}
	}

	// Using credential’s id attribute (or the corresponding rawId, if base64url encoding is inappropriate for your use
	// case), look up the corresponding credential public key.
	authr, err := w.Config.AuthenticatorStore.GetAuthenticator(p.RawID)
	if err != nil {
		w.writeError(r, rw, err)
		return nil
	}

	block, _ := pem.Decode(authr.WebAuthPublicKey())
	if block == nil {
		w.writeError(r, rw, fmt.Errorf("invalid stored public key, unable to decode"))
		return nil
	}

	cert, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		w.writeError(r, rw, err)
		return nil
	}

	valid, err := protocol.IsValidAssertion(p, chal, w.Config.RelyingPartyID, w.Config.RelyingPartyOrigin, &x509.Certificate{
		PublicKey: cert,
	})
	if err != nil {
		w.writeError(r, rw, err)
		return nil
	}

	if !valid {
		w.writeError(r, rw, protocol.ErrInvalidRequest.WithDebug("invalid login"))
		return nil
	}

	return authr
}
