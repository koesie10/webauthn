package protocol_test

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"testing"

	"go.vasystem.org/services/accounts/webauthn/protocol"
)

func TestIsValidAttestation(t *testing.T) {
	r := protocol.CredentialCreationOptions{}
	if err := json.Unmarshal([]byte(attestationRequest), &r); err != nil {
		t.Fatal(err)
	}

	b := protocol.AttestationResponse{}
	if err := json.Unmarshal([]byte(attestationResponse), &b); err != nil {
		t.Fatal(err)
	}

	p, err := protocol.ParseAttestationResponse(b)
	if err != nil {
		t.Fatal(err)
	}

	d, err := protocol.IsValidAttestation(p, r.PublicKey.Challenge, "")
	if err != nil {
		t.Fatal(err)
	}

	if !d {
		t.Fatal("is not valid")
	}
}

func TestIsValidAssertion(t *testing.T) {
	block, _ := pem.Decode([]byte(attestationPublicKey))
	if block == nil {
		t.Fatal("invalid public key")
	}

	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	cert := &x509.Certificate{
		PublicKey: publicKey,
	}

	r := protocol.CredentialCreationOptions{}
	if err := json.Unmarshal([]byte(assertionRequest), &r); err != nil {
		t.Fatal(err)
	}

	b := protocol.AssertionResponse{}
	if err := json.Unmarshal([]byte(assertionResponse), &b); err != nil {
		t.Fatal(err)
	}

	p, err := protocol.ParseAssertionResponse(b)
	if err != nil {
		t.Fatal(err)
	}

	d, err := protocol.IsValidAssertion(p, r.PublicKey.Challenge, "", cert)
	if err != nil {
		t.Fatal(err)
	}

	if !d {
		t.Fatal("is not valid")
	}
}

const attestationRequest = `{"publicKey":{"rp":{"name":"accountsvc"},"user":{"id":"MTAwNjg1ODU4NDE3ODI5NDc4NA==","name":"Koen Vlaswinkel","displayName":"Koen Vlaswinkel"},"pubKeyCredParams":[{"type":"public-key","alg":-7}],"timeout":10000,"attestation":"direct","challenge":"+1jQysnwaIjNU+GrwRp4PWNBMlX0i9/caRkcKd7LPj8="}}`
const attestationResponse = `{"id":"LOXI3xfiLvIP04MD_S2ZmJYwn3cvMX1FUXxiQO7xlfUvrfcj99UVO2aMrMAwsGvsujY7NHWiM6G3B6ryKJDBBdab-cl4tVZeOwOMhgvHLXk","rawId":"LOXI3xfiLvIP04MD/S2ZmJYwn3cvMX1FUXxiQO7xlfUvrfcj99UVO2aMrMAwsGvsujY7NHWiM6G3B6ryKJDBBdab+cl4tVZeOwOMhgvHLXk=","response":{"attestationObject":"o2dhdHRTdG10omNzaWdYRjBEAiAJ8Q7i8DQzKlb00g4Wby4PoEjlI+s3bS+kVKI3PKoyXQIgDzcP2c5vpplZdmftN+zUDNfXtG1TniWbJv2+6kGZ8bljeDVjgVkBKzCCAScwgc6gAwIBAgIBADAKBggqhkjOPQQDAjAWMRQwEgYDVQQDDAtLcnlwdG9uIEtleTAeFw0xODA5MTcxODQ3NDJaFw0yODA5MTcxODQ3NDJaMBYxFDASBgNVBAMMC0tyeXB0b24gS2V5MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEwzIpvM5A6mZQXYxRIhfp0sb/21yTcr/sp5Y5DU0IWODQf5ldS2rlDCl62yEaQDM9Akxbsay/vA/S5ut4VSsvoKMNMAswCQYDVR0TBAIwADAKBggqhkjOPQQDAgNIADBFAiA4Yx+5MtKVnjme6V3qXKQ2qcgaHfO6DMgXM9kwOCZcNAIhAJdNk5PPSA04ITfrX9HQy5azo8sH9yhkW7c6gLdb/Kz+aGF1dGhEYXRhWNRJlg3liA6MaHQ0Fw9kdmBbj+SuuaKGMseZXPO6gx2XY0EAAAAALOXI3xfiLvIP04MD/S2ZmABQLOXI3xfiLvIP04MD/S2ZmJYwn3cvMX1FUXxiQO7xlfUvrfcj99UVO2aMrMAwsGvsujY7NHWiM6G3B6ryKJDBBdab+cl4tVZeOwOMhgvHLXmlAQIDJiABIVggwzIpvM5A6mZQXYxRIhfp0sb/21yTcr/sp5Y5DU0IWOAiWCDQf5ldS2rlDCl62yEaQDM9Akxbsay/vA/S5ut4VSsvoGNmbXRoZmlkby11MmY=","clientDataJSON":"eyJjaGFsbGVuZ2UiOiItMWpReXNud2FJak5VLUdyd1JwNFBXTkJNbFgwaTlfY2FSa2NLZDdMUGo4IiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDo1Mzg3OSIsInRva2VuQmluZGluZyI6eyJzdGF0dXMiOiJub3Qtc3VwcG9ydGVkIn0sInR5cGUiOiJ3ZWJhdXRobi5jcmVhdGUifQ=="},"type":"public-key"}`

const assertionRequest = `{"publicKey":{"allowCredentials":[{"id":"LOXI3xfiLvIP04MD/S2ZmJYwn3cvMX1FUXxiQO7xlfUvrfcj99UVO2aMrMAwsGvsujY7NHWiM6G3B6ryKJDBBdab+cl4tVZeOwOMhgvHLXk=","type":"public-key"}],"challenge":"+c0hMsULvTWp6ASl45YyOQRA/yVVK60XccCQ+Vui9j8=","timeout":10000}}`
const assertionResponse = `{"id":"LOXI3xfiLvIP04MD_S2ZmJYwn3cvMX1FUXxiQO7xlfUvrfcj99UVO2aMrMAwsGvsujY7NHWiM6G3B6ryKJDBBdab-cl4tVZeOwOMhgvHLXk","rawId":"LOXI3xfiLvIP04MD/S2ZmJYwn3cvMX1FUXxiQO7xlfUvrfcj99UVO2aMrMAwsGvsujY7NHWiM6G3B6ryKJDBBdab+cl4tVZeOwOMhgvHLXk=","response":{"clientDataJSON":"eyJjaGFsbGVuZ2UiOiItYzBoTXNVTHZUV3A2QVNsNDVZeU9RUkFfeVZWSzYwWGNjQ1EtVnVpOWo4IiwiaGFzaEFsZ29yaXRobSI6IlNIQS0yNTYiLCJvcmlnaW4iOiJodHRwOi8vbG9jYWxob3N0OjUzODc5IiwidHlwZSI6IndlYmF1dGhuLmdldCJ9","authenticatorData":"SZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2MBAAAAAQ==","signature":"MEYCIQD7W6TPIviP+BztYxEMsan/esy/O0S4pJO+9QxDaA0ehAIhANo5D+5UxwbtJGFcvSryl0+RdJd3j4lIKVhEe7WpvZeV","userHandle":""},"type":"public-key"}`

const attestationPublicKey = `-----BEGIN CERTIFICATE-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEwzIpvM5A6mZQXYxRIhfp0sb/21yT
cr/sp5Y5DU0IWODQf5ldS2rlDCl62yEaQDM9Akxbsay/vA/S5ut4VSsvoA==
-----END CERTIFICATE-----`
