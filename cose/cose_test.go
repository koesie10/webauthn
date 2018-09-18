package cose_test

import (
	"crypto/ecdsa"
	"testing"

	"github.com/koesie10/webauthn/cose"
)

func TestParseCOSE(t *testing.T) {
	key, err := cose.ParseCOSE(coseKey)
	if err != nil {
		t.Fatal(err)
	}

	_ = key.(*ecdsa.PublicKey)
}

var coseKey = []byte{165, 1, 2, 3, 38, 32, 1, 33, 88, 32, 216, 135, 166, 35, 155, 95, 158, 137, 152, 93, 252, 213, 238, 69, 20, 97, 196, 158, 87, 181, 241, 175, 77, 207, 20, 244, 241, 201, 179, 138, 100, 239, 34, 88, 32, 163, 48, 62, 105, 84, 41, 231, 50, 219, 25, 77, 105, 244, 230, 187, 108, 215, 105, 155, 163, 198, 146, 133, 33, 252, 5, 101, 90, 174, 75, 99, 141}
