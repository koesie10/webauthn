package webauthn

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"

	"github.com/koesie10/webauthn/protocol"
)

// GetRegistrationOptions will return the options that need to be passed to navigator.credentials.create(). This should
// be returned to the user via e.g. JSON over HTTP. For convenience, use StartRegistration.
func (w *WebAuthn) GetRegistrationOptions(user User, session Session) (*protocol.CredentialCreationOptions, error) {
	chal, err := protocol.NewChallenge()
	if err != nil {
		return nil, err
	}

	u := protocol.PublicKeyCredentialUserEntity{
		ID: user.WebAuthID(),
		PublicKeyCredentialEntity: protocol.PublicKeyCredentialEntity{
			Name: user.WebAuthName(),
		},
		DisplayName: user.WebAuthDisplayName(),
	}

	options := &protocol.CredentialCreationOptions{
		PublicKey: protocol.PublicKeyCredentialCreationOptions{
			Challenge: chal,
			RP: protocol.PublicKeyCredentialRpEntity{
				ID: w.Config.RelyingPartyID,
				PublicKeyCredentialEntity: protocol.PublicKeyCredentialEntity{
					Name: w.Config.RelyingPartyName,
				},
			},
			PubKeyCredParams: []protocol.PublicKeyCredentialParameters{
				{
					Type:      protocol.PublicKeyCredentialTypePublicKey,
					Algorithm: protocol.ES256,
				},
			},
			Timeout:     w.Config.Timeout,
			User:        u,
			Attestation: protocol.AttestationConveyancePreferenceDirect,
		},
	}

	authenticators, err := w.Config.AuthenticatorStore.GetAuthenticators(user)
	if err != nil {
		return nil, err
	}

	excludeCredentials := make([]protocol.PublicKeyCredentialDescriptor, len(authenticators))

	for i, authr := range authenticators {
		excludeCredentials[i] = protocol.PublicKeyCredentialDescriptor{
			ID:   authr.WebAuthCredentialID(),
			Type: protocol.PublicKeyCredentialTypePublicKey,
		}
	}

	options.PublicKey.ExcludeCredentials = excludeCredentials

	if err := session.Set(w.Config.SessionKeyPrefixChallenge+".register", []byte(chal)); err != nil {
		return nil, err
	}
	if err := session.Set(w.Config.SessionKeyPrefixUserID+".register", u.ID); err != nil {
		return nil, err
	}

	return options, nil
}

// StartRegistration is a HTTP request handler which writes the options to be passed to navigator.credentials.create()
// to the http.ResponseWriter.
func (w *WebAuthn) StartRegistration(r *http.Request, rw http.ResponseWriter, user User, session Session) {
	options, err := w.GetRegistrationOptions(user, session)
	if err != nil {
		w.writeError(r, rw, err)
		return
	}

	w.write(r, rw, options)
}

// ParseAndFinishRegistration should receive the response of navigator.credentials.create(). If
// the request is valid, AuthenticatorStore.AddAuthenticator will be called and the authenticator that was registered
// will be returned. For convenience, use FinishRegistration.
func (w *WebAuthn) ParseAndFinishRegistration(attestationResponse protocol.AttestationResponse, user User, session Session) (Authenticator, error) {
	rawChal, err := session.Get(w.Config.SessionKeyPrefixChallenge + ".register")
	if err != nil {
		return nil, protocol.ErrInvalidRequest.WithDebug("missing challenge in session")
	}
	chal, ok := rawChal.([]byte)
	if !ok {
		return nil, protocol.ErrInvalidRequest.WithDebug("invalid challenge session value")
	}
	if err := session.Delete(w.Config.SessionKeyPrefixChallenge + ".register"); err != nil {
		return nil, err
	}

	rawUserID, err := session.Get(w.Config.SessionKeyPrefixUserID + ".register")
	if err != nil {
		return nil, protocol.ErrInvalidRequest.WithDebug("missing user ID in session")
	}
	userID, ok := rawUserID.([]byte)
	if !ok {
		return nil, protocol.ErrInvalidRequest.WithDebug("invalid user ID session value")
	}
	if err := session.Delete(w.Config.SessionKeyPrefixUserID + ".register"); err != nil {
		return nil, err
	}

	if !bytes.Equal(user.WebAuthID(), userID) {
		return nil, protocol.ErrInvalidRequest.WithDebug("user has changed since start of registration")
	}

	p, err := protocol.ParseAttestationResponse(attestationResponse)
	if err != nil {
		return nil, err
	}

	valid, err := protocol.IsValidAttestation(p, chal, w.Config.RelyingPartyID, w.Config.RelyingPartyOrigin)
	if err != nil {
		return nil, err
	}

	if !valid {
		return nil, protocol.ErrInvalidRequest.WithDebug("invalid registration")
	}

	data, err := x509.MarshalPKIXPublicKey(p.Response.Attestation.AuthData.AttestedCredentialData.COSEKey)
	if err != nil {
		return nil, err
	}

	authr := &defaultAuthenticator{
		id:           p.RawID,
		credentialID: p.Response.Attestation.AuthData.AttestedCredentialData.CredentialID,
		publicKey: pem.EncodeToMemory(&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: data,
		}),
		aaguid:    p.Response.Attestation.AuthData.AttestedCredentialData.AAGUID,
		signCount: p.Response.Attestation.AuthData.SignCount,
	}

	if err := w.Config.AuthenticatorStore.AddAuthenticator(user, authr); err != nil {
		return nil, err
	}

	return authr, nil
}

// FinishRegistration is a HTTP request handler which should receive the response of navigator.credentials.create(). If
// the request is valid, AuthenticatorStore.AddAuthenticator will be called and an empty response with HTTP status code
// 201 (Created) will be written to the http.ResponseWriter. If authenticator is  nil, an error has been written to
// http.ResponseWriter and should be returned as-is.
func (w *WebAuthn) FinishRegistration(r *http.Request, rw http.ResponseWriter, user User, session Session) Authenticator {
	var attestationResponse protocol.AttestationResponse
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(&attestationResponse); err != nil {
		w.writeError(r, rw, protocol.ErrInvalidRequest.WithDebug(err.Error()))
		return nil
	}

	authr, err := w.ParseAndFinishRegistration(attestationResponse, user, session)
	if err != nil {
		w.writeError(r, rw, err)
		return nil
	}

	rw.WriteHeader(http.StatusCreated)

	return authr
}
