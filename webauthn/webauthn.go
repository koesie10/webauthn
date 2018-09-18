package webauthn

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/pkg/errors"
	"github.com/koesie10/webauthn/protocol"
)

// WebAuthN is the primary interface of this package and contains the request handlers that should be called.
type WebAuthN struct {
	Config *Config
}

// New creates a new WebAuthN based on the given Config. The Config will be validated and an error will be returned
// if it is invalid.
func New(c *Config) (*WebAuthN, error) {
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("failed to validate config: %v", err)
	}
	return &WebAuthN{
		Config: c,
	}, nil
}

func (w *WebAuthN) write(r *http.Request, rw http.ResponseWriter, res interface{}) {
	w.writeCode(r, rw, http.StatusOK, res)
}

func (w *WebAuthN) writeCode(r *http.Request, rw http.ResponseWriter, code int, res interface{}) {
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

func (w *WebAuthN) writeError(r *http.Request, rw http.ResponseWriter, err error) {
	if v, ok := errors.Cause(err).(*protocol.Error); ok {
		w.writeErrorCode(r, rw, v.Code, err)
		return
	}

	w.writeErrorCode(r, rw, http.StatusInternalServerError, err)
}

func (w *WebAuthN) writeErrorCode(r *http.Request, rw http.ResponseWriter, code int, err error) {
	e := protocol.ToWebAuthNError(err)

	if code == 0 {
		code = http.StatusInternalServerError
	}

	js, err := json.Marshal(e)
	if err != nil {
		w.writeError(r, rw, err)
		return
	}

	if !w.Config.Debug {
		e.Debug = ""
	}

	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(code)
	rw.Write(js)
}
