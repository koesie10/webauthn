# webauthn : Web Authentication API in Go

## Overview [![GoDoc](https://godoc.org/github.com/koesie10/webauthn?status.svg)](https://godoc.org/github.com/koesie10/webauthn) [![Build Status](https://travis-ci.org/koesie10/webauthn.svg?branch=master)](https://travis-ci.org/koesie10/webauthn)

This project provides a low-level and a high-level API to use the [Web Authentication API](https://www.w3.org/TR/webauthn/) (WebAuthn).

[Demo](https://github.com/koesie10/webauthn-demo)

## Install

```
go get github.com/koesie10/webauthn
```

## High-level API

The high-level API can be used with the `net/http` package and simplifies the low-level API. It is located in the `webauthn` subpackage. It is intended
for use with e.g. `fetch` or `XMLHttpRequest` JavaScript clients.

First, make sure your user entity implements [`User`](https://godoc.org/github.com/koesie10/webauthn/webauthn#User). Then, create a new entity
implements [`Authenticator`](https://godoc.org/github.com/koesie10/webauthn/webauthn#Authenticator) that stores each authenticator the user
registers.

Then, either make your existing repository implement [`AuthenticatorStore`](https://godoc.org/github.com/koesie10/webauthn/webauthn#AuthenticatorStore)
or create a new repository.

Finally, you can create the main [`WebAuthn`](https://godoc.org/github.com/koesie10/webauthn/webauthn#WebAuthn) struct supplying the
[`Config`](https://godoc.org/github.com/koesie10/webauthn/webauthn#Config) options:

```golang
w, err := webauthn.New(&webauthn.Config{
	// A human-readable identifier for the relying party (i.e. your app), intended only for display.
	RelyingPartyName:   "webauthn-demo",
	// Storage for the authenticator.
	AuthenticatorStore: storage,
})		
```

Then, you can use the methods defined, such as [`StartRegistration`](https://godoc.org/github.com/koesie10/webauthn/webauthn#WebAuthn.StartRegistration)
to handle registration and login. Every handler requires a [`Session`](https://godoc.org/github.com/koesie10/webauthn/webauthn#Session), which stores
intermediate registration/login data. If you use [`gorilla/sessions`](https://github.com/gorilla/sessions), use
[`webauthn.WrapMap`](https://godoc.org/github.com/koesie10/webauthn/webauthn#WrapMap)`(session.Values)`. Read the documentation for complete information
on what parameters need to be passed and what values are returned.

For example, a handler for finish registration might look like this:

```golang
func (r *http.Request, rw http.ResponseWriter) {
	ctx := r.Context()
	user, ok := UserFromContext(ctx)
	if !ok {
		rw.WriteHeader(http.StatusForbidden)
		return
	}

	sess := SessionFromContext(c)

	h.webauthn.FinishRegistration(c.Request(), c.Response(), user, webauthn.WrapMap(sess))
}
```

A complete demo application using the high-level API which implements all of these interfaces and stores data in memory is available
[here](https://github.com/koesie10/webauthn-demo).

## JavaScript example

[This class](webauthn.js) is an example that can be used to handle the registration and login phases. It can be used as follows:

```javascript
const w = new WebAuthn();

// Registration
w.register().then(() => {
	alert('This authenticator has been registered.');
}).catch(err => {
	console.error(err)
	alert('Failed to register: ' + err);
});

// Login
w.login().then(() => {
	alert('You have been logged in.');
}).catch(err => {
	console.error(err)
	alert('Failed to login: ' + err);
});
```

## Low-level API

The low-level closely resembles the specification and the high-level API should be preferred. However, if you would like to use the low-level
API, the main entry points are:

* [`ParseAttestationResponse`](https://godoc.org/github.com/koesie10/webauthn/protocol#ParseAttestationResponse)
* [`IsValidAttestation`](https://godoc.org/github.com/koesie10/webauthn/protocol#IsValidAttestation)
* [`ParseAssertionResponse`](https://godoc.org/github.com/koesie10/webauthn/protocol#ParseAssertionResponse)
* [`IsValidAssertion`](https://godoc.org/github.com/koesie10/webauthn/protocol#IsValidAssertion)

## License

MIT.
