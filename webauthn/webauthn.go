package webauthn

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/koesie10/webauthn/protocol"
	"github.com/pkg/errors"
)

// WebAuthn is the primary interface of this package and contains the request handlers that should be called.
type WebAuthn struct {
	Config *Config
}

// New creates a new WebAuthn based on the given Config. The Config will be validated and an error will be returned
// if it is invalid.
func New(c *Config) (*WebAuthn, error) {
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("failed to validate config: %v", err)
	}
	return &WebAuthn{
		Config: c,
	}, nil
}

func (w *WebAuthn) write(r *http.Request, rw http.ResponseWriter, res interface{}) {
	w.writeCode(r, rw, http.StatusOK, res)
}

func (w *WebAuthn) writeCode(r *http.Request, rw http.ResponseWriter, code int, res interface{}) {
	js, err := json.Marshal(res)
	if err != nil {
		w.writeError(r, rw, err)
		return
	}

	if code == 0 {
		code = http.StatusOK
	}

	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(code)
	rw.Write(js)
}

func (w *WebAuthn) writeError(r *http.Request, rw http.ResponseWriter, err error) {
	if v, ok := errors.Cause(err).(*protocol.Error); ok {
		w.writeErrorCode(r, rw, v.Code, err)
		return
	}

	w.writeErrorCode(r, rw, http.StatusInternalServerError, err)
}

func (w *WebAuthn) writeErrorCode(r *http.Request, rw http.ResponseWriter, code int, err error) {
	e := protocol.ToWebAuthnError(err)

	if code == 0 {
		code = http.StatusInternalServerError
	}

	if !w.Config.Debug {
		e.Debug = ""
	}

	js, err := json.Marshal(e)
	if err != nil {
		w.writeError(r, rw, err)
		return
	}

	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(code)
	rw.Write(js)
}
