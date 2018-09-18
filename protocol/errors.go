package protocol

import (
	"fmt"
	"net/http"

	"github.com/pkg/errors"
)

// Default errors
var (
	ErrInvalidSignature = &Error{
		Name:        "invalid_signature",
		Description: "The signature is invalid",
		Hint:        "Check that the provided token is in the correct format",
		Code:        http.StatusUnauthorized,
	}
	ErrInvalidRequest = &Error{
		Name:        "invalid_request",
		Description: "The request is malformed",
		Hint:        "Make sure that the parameters provided are correct",
		Code:        http.StatusBadRequest,
	}
	ErrUnsupportedAttestationFormat = &Error{
		Name:        "unsupported_attestation_format",
		Description: "The attestation format is unsupported",
		Code:        http.StatusBadRequest,
	}
	ErrInvalidAttestation = &Error{
		Name:        "invalid_attestation",
		Description: "The attestation is malformed",
		Hint:        "Check that you provided a token in the right format.",
		Code:        http.StatusBadRequest,
	}
	ErrInvalidType = &Error{
		Name:        "invalid_type",
		Description: "The attestion/assertion type is invalid",
		Hint:        "Check that the client data was submitted for the right call",
		Code:        http.StatusBadRequest,
	}
	ErrInvalidChallenge = &Error{
		Name:        "invalid_challenge",
		Description: "The challenge is invalid",
		Hint:        "Check that the challenge was supplied for the right request",
		Code:        http.StatusBadRequest,
	}
	ErrInvalidOrigin = &Error{
		Name:        "invalid_origin",
		Description: "The origin is invalid",
		Code:        http.StatusBadRequest,
	}
	ErrNoUserPresent = &Error{
		Name:        "no_user_present",
		Description: "No user was presented during authentication",
		Code:        http.StatusBadRequest,
	}
)

// Error is a representation of errors returned from this package.
type Error struct {
	// Name is the name of this error.
	Name string `json:"error"`
	// Description is the description of this error.
	Description string `json:"description"`
	// Hint contains further information about the error.
	Hint string `json:"hint,omitempty"`
	// Code contains the status code that should be returned when this error is returned.
	Code int `json:"status_code,omitempty"`
	// Debug contains debug information about this error that should not be shown to the user.
	Debug string `json:"debug,omitempty"`
}

// ToWebAuthnError converts any error into the *Error type. If that is not possible, it will return an *Error
// which wraps the error.
func ToWebAuthnError(err error) *Error {
	if e, ok := err.(*Error); ok {
		return e
	} else if e, ok := errors.Cause(err).(*Error); ok {
		return e
	}
	return &Error{
		Name:        "error",
		Description: "This error was not recognized",
		Debug:       err.Error(),
		Code:        http.StatusInternalServerError,
	}
}

// Error implements the error interface.
func (e *Error) Error() string {
	return e.Name
}

// WithHintf will add/replace the hint of the error.
func (e *Error) WithHintf(hint string, args ...interface{}) *Error {
	return e.WithHint(fmt.Sprintf(hint, args...))
}

// WithHint will add/replace the hint of the error.
func (e *Error) WithHint(hint string) *Error {
	err := *e
	err.Hint = hint
	return &err
}

// WithDebugf will add/replace the debug information of the error.
func (e *Error) WithDebugf(debug string, args ...interface{}) *Error {
	return e.WithDebug(fmt.Sprintf(debug, args...))
}

// WithDebug will add/replace the debug information of the error.
func (e *Error) WithDebug(debug string) *Error {
	err := *e
	err.Debug = debug
	return &err
}
