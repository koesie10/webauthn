package cose

import (
	"bytes"
	"fmt"

	"github.com/ugorji/go/codec"
)

// Errors
var (
	ErrMissingKeyType       = fmt.Errorf("cose: missing key type")
	ErrMissingAlgorithm     = fmt.Errorf("cose: missing algorithm")
	ErrUnsupportedKeyType   = fmt.Errorf("cose: unsupported key type")
	ErrUnsupportedAlgorithm = fmt.Errorf("cose: unsupported algorithm")
	ErrInvalidFormat        = fmt.Errorf("cose: invalid format")
)

// ParseCOSE parses a raw COSE key into a public key, either *ecdsa.PublicKey or *rsa.PublicKey.
func ParseCOSE(buf []byte) (interface{}, error) {
	m := make(map[int]interface{})

	cbor := codec.CborHandle{}

	if err := codec.NewDecoder(bytes.NewReader(buf), &cbor).Decode(&m); err != nil {
		return nil, err
	}

	return ParseCOSEMap(m)
}

// ParseCOSEMap parses a COSE key that has been decoded from it's CBOR format to a dictionary.
func ParseCOSEMap(m map[int]interface{}) (interface{}, error) {
	rawKty, ok := m[1]
	if !ok {
		return nil, ErrMissingKeyType
	}
	kty, ok := rawKty.(uint64)
	if !ok {
		return nil, ErrMissingKeyType
	}

	rawAlg, ok := m[3]
	if !ok {
		return nil, ErrMissingAlgorithm
	}
	alg, ok := rawAlg.(int64)
	if !ok {
		return nil, ErrMissingAlgorithm
	}

	// https://tools.ietf.org/html/rfc8152#section-13
	switch kty {
	case 2: // EC2
		return parseECDSA(alg, m)
	default:
		return nil, ErrUnsupportedKeyType
	}
}
