package protocol_test

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"testing"

	"github.com/koesie10/webauthn/protocol"
)

func TestIsValidAttestation(t *testing.T) {
	for i := range attestationRequests {
		t.Run(fmt.Sprintf("Run %d", i), func(t *testing.T) {
			r := protocol.CredentialCreationOptions{}
			if err := json.Unmarshal([]byte(attestationRequests[i]), &r); err != nil {
				t.Fatal(err)
			}

			b := protocol.AttestationResponse{}
			if err := json.Unmarshal([]byte(attestationResponses[i]), &b); err != nil {
				t.Fatal(err)
			}

			p, err := protocol.ParseAttestationResponse(b)
			if err != nil {
				t.Fatal(err)
			}

			d, err := protocol.IsValidAttestation(p, r.PublicKey.Challenge, "", "")
			if err != nil {
				e := protocol.ToWebAuthnError(err)
				t.Fatal(fmt.Sprintf("%s, %s: %s", e.Name, e.Description, e.Debug))
			}

			if !d {
				t.Fatal("is not valid")
			}
		})
	}
}

func TestIsValidAssertion(t *testing.T) {
	for i := range assertionRequests {
		t.Run(fmt.Sprintf("Run %d", i), func(t *testing.T) {
			block, _ := pem.Decode([]byte(attestationPublicKeys[i]))
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
			if err := json.Unmarshal([]byte(assertionRequests[i]), &r); err != nil {
				t.Fatal(err)
			}

			b := protocol.AssertionResponse{}
			if err := json.Unmarshal([]byte(assertionResponses[i]), &b); err != nil {
				t.Fatal(err)
			}

			p, err := protocol.ParseAssertionResponse(b)
			if err != nil {
				t.Fatal(err)
			}

			d, err := protocol.IsValidAssertion(p, r.PublicKey.Challenge, "", "", cert)
			if err != nil {
				t.Fatal(err)
			}

			if !d {
				t.Fatal("is not valid")
			}
		})
	}
}

var attestationRequests = []string{
	`{"publicKey":{"rp":{"name":"accountsvc"},"user":{"id":"MTAwNjg1ODU4NDE3ODI5NDc4NA==","name":"Koen Vlaswinkel","displayName":"Koen Vlaswinkel"},"pubKeyCredParams":[{"type":"public-key","alg":-7}],"timeout":10000,"attestation":"direct","challenge":"+1jQysnwaIjNU+GrwRp4PWNBMlX0i9/caRkcKd7LPj8="}}`,
	`{"publicKey":{"rp":{"name":"webauthn-demo"},"user":{"name":"koen","id":"a29lbg==","displayName":"koen"},"challenge":"JUtlYcgpkSiFNzsThDYuOrtSVY1VeLofM+mWTRCCXqU=","pubKeyCredParams":[{"type":"public-key","alg":-7}],"timeout":30000,"authenticatorSelection":{"requireResidentKey":false},"attestation":"direct"}}`,
}

var attestationResponses = []string{
	`{"id":"LOXI3xfiLvIP04MD_S2ZmJYwn3cvMX1FUXxiQO7xlfUvrfcj99UVO2aMrMAwsGvsujY7NHWiM6G3B6ryKJDBBdab-cl4tVZeOwOMhgvHLXk","rawId":"LOXI3xfiLvIP04MD/S2ZmJYwn3cvMX1FUXxiQO7xlfUvrfcj99UVO2aMrMAwsGvsujY7NHWiM6G3B6ryKJDBBdab+cl4tVZeOwOMhgvHLXk=","response":{"attestationObject":"o2dhdHRTdG10omNzaWdYRjBEAiAJ8Q7i8DQzKlb00g4Wby4PoEjlI+s3bS+kVKI3PKoyXQIgDzcP2c5vpplZdmftN+zUDNfXtG1TniWbJv2+6kGZ8bljeDVjgVkBKzCCAScwgc6gAwIBAgIBADAKBggqhkjOPQQDAjAWMRQwEgYDVQQDDAtLcnlwdG9uIEtleTAeFw0xODA5MTcxODQ3NDJaFw0yODA5MTcxODQ3NDJaMBYxFDASBgNVBAMMC0tyeXB0b24gS2V5MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEwzIpvM5A6mZQXYxRIhfp0sb/21yTcr/sp5Y5DU0IWODQf5ldS2rlDCl62yEaQDM9Akxbsay/vA/S5ut4VSsvoKMNMAswCQYDVR0TBAIwADAKBggqhkjOPQQDAgNIADBFAiA4Yx+5MtKVnjme6V3qXKQ2qcgaHfO6DMgXM9kwOCZcNAIhAJdNk5PPSA04ITfrX9HQy5azo8sH9yhkW7c6gLdb/Kz+aGF1dGhEYXRhWNRJlg3liA6MaHQ0Fw9kdmBbj+SuuaKGMseZXPO6gx2XY0EAAAAALOXI3xfiLvIP04MD/S2ZmABQLOXI3xfiLvIP04MD/S2ZmJYwn3cvMX1FUXxiQO7xlfUvrfcj99UVO2aMrMAwsGvsujY7NHWiM6G3B6ryKJDBBdab+cl4tVZeOwOMhgvHLXmlAQIDJiABIVggwzIpvM5A6mZQXYxRIhfp0sb/21yTcr/sp5Y5DU0IWOAiWCDQf5ldS2rlDCl62yEaQDM9Akxbsay/vA/S5ut4VSsvoGNmbXRoZmlkby11MmY=","clientDataJSON":"eyJjaGFsbGVuZ2UiOiItMWpReXNud2FJak5VLUdyd1JwNFBXTkJNbFgwaTlfY2FSa2NLZDdMUGo4IiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDo1Mzg3OSIsInRva2VuQmluZGluZyI6eyJzdGF0dXMiOiJub3Qtc3VwcG9ydGVkIn0sInR5cGUiOiJ3ZWJhdXRobi5jcmVhdGUifQ=="},"type":"public-key"}`,
	`{"id":"SNBSJTt1DHEuG9XBd6lfc4XXqxkppWfFbt4P5sRVQEPIPANIHHCmPo1AwY5pkUGcpVL3W-uHyWEn4vbgzp34Qw","rawId":"SNBSJTt1DHEuG9XBd6lfc4XXqxkppWfFbt4P5sRVQEPIPANIHHCmPo1AwY5pkUGcpVL3W+uHyWEn4vbgzp34Qw==","response":{"attestationObject":"o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEcwRQIgFls/elhmdZmqEBEKafdcyvQPDrTdBRMW92v6RKJj1bACIQCZ+46sXn65dMEpPuGxvMUruV5i7XN25ctFV/iAi3wSomN4NWOBWQLCMIICvjCCAaagAwIBAgIEdIb9wjANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowbzELMAkGA1UEBhMCU0UxEjAQBgNVBAoMCVl1YmljbyBBQjEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjEoMCYGA1UEAwwfWXViaWNvIFUyRiBFRSBTZXJpYWwgMTk1NTAwMzg0MjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJVd8633JH0xde/9nMTzGk6HjrrhgQlWYVD7OIsuX2Unv1dAmqWBpQ0KxS8YRFwKE1SKE1PIpOWacE5SO8BN6+2jbDBqMCIGCSsGAQQBgsQKAgQVMS4zLjYuMS40LjEuNDE0ODIuMS4xMBMGCysGAQQBguUcAgEBBAQDAgUgMCEGCysGAQQBguUcAQEEBBIEEPigEfOMCk0VgAYXER+e3H0wDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAQEAMVxIgOaaUn44Zom9af0KqG9J655OhUVBVW+q0As6AIod3AH5bHb2aDYakeIyyBCnnGMHTJtuekbrHbXYXERIn4aKdkPSKlyGLsA/A+WEi+OAfXrNVfjhrh7iE6xzq0sg4/vVJoywe4eAJx0fS+Dl3axzTTpYl71Nc7p/NX6iCMmdik0pAuYJegBcTckE3AoYEg4K99AM/JaaKIblsbFh8+3LxnemeNf7UwOczaGGvjS6UzGVI0Odf9lKcPIwYhuTxM5CaNMXTZQ7xq4/yTfC3kPWtE4hFT34UJJflZBiLrxG4OsYxkHw/n5vKgmpspB3GfYuYTWhkDKiE8CYtyg87mhhdXRoRGF0YVjESZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2NBAAAAA/igEfOMCk0VgAYXER+e3H0AQEjQUiU7dQxxLhvVwXepX3OF16sZKaVnxW7eD+bEVUBDyDwDSBxwpj6NQMGOaZFBnKVS91vrh8lhJ+L24M6d+EOlAQIDJiABIVggLxxTguKmjCV4N5OMqd2Sl9AIxSltaPevmQxSqnyNlAciWCDEHOaQDaZ6pC2gC+Z0KS4Ln/XQiJp0X1BmTd+K+FdqSg==","clientDataJSON":"eyJjaGFsbGVuZ2UiOiJKVXRsWWNncGtTaUZOenNUaERZdU9ydFNWWTFWZUxvZk0tbVdUUkNDWHFVIiwibmV3X2tleXNfbWF5X2JlX2FkZGVkX2hlcmUiOiJkbyBub3QgY29tcGFyZSBjbGllbnREYXRhSlNPTiBhZ2FpbnN0IGEgdGVtcGxhdGUuIFNlZSBodHRwczovL2dvby5nbC95YWJQZXgiLCJvcmlnaW4iOiJodHRwOi8vbG9jYWxob3N0OjkwMDAiLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0="},"type":"public-key"}`,
}

var assertionRequests = []string{
	`{"publicKey":{"allowCredentials":[{"id":"LOXI3xfiLvIP04MD/S2ZmJYwn3cvMX1FUXxiQO7xlfUvrfcj99UVO2aMrMAwsGvsujY7NHWiM6G3B6ryKJDBBdab+cl4tVZeOwOMhgvHLXk=","type":"public-key"}],"challenge":"+c0hMsULvTWp6ASl45YyOQRA/yVVK60XccCQ+Vui9j8=","timeout":10000}}`,
	`{"publicKey":{"challenge":"mcPXIDRHSPBF2gJWU58GPrR3TodLDXR1kHJhgVanYnU=","timeout":30000,"allowCredentials":[{"type":"public-key","id":"SNBSJTt1DHEuG9XBd6lfc4XXqxkppWfFbt4P5sRVQEPIPANIHHCmPo1AwY5pkUGcpVL3W+uHyWEn4vbgzp34Qw=="}]}}`,
}

var assertionResponses = []string{
	`{"id":"LOXI3xfiLvIP04MD_S2ZmJYwn3cvMX1FUXxiQO7xlfUvrfcj99UVO2aMrMAwsGvsujY7NHWiM6G3B6ryKJDBBdab-cl4tVZeOwOMhgvHLXk","rawId":"LOXI3xfiLvIP04MD/S2ZmJYwn3cvMX1FUXxiQO7xlfUvrfcj99UVO2aMrMAwsGvsujY7NHWiM6G3B6ryKJDBBdab+cl4tVZeOwOMhgvHLXk=","response":{"clientDataJSON":"eyJjaGFsbGVuZ2UiOiItYzBoTXNVTHZUV3A2QVNsNDVZeU9RUkFfeVZWSzYwWGNjQ1EtVnVpOWo4IiwiaGFzaEFsZ29yaXRobSI6IlNIQS0yNTYiLCJvcmlnaW4iOiJodHRwOi8vbG9jYWxob3N0OjUzODc5IiwidHlwZSI6IndlYmF1dGhuLmdldCJ9","authenticatorData":"SZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2MBAAAAAQ==","signature":"MEYCIQD7W6TPIviP+BztYxEMsan/esy/O0S4pJO+9QxDaA0ehAIhANo5D+5UxwbtJGFcvSryl0+RdJd3j4lIKVhEe7WpvZeV","userHandle":""},"type":"public-key"}`,
	`{"id":"SNBSJTt1DHEuG9XBd6lfc4XXqxkppWfFbt4P5sRVQEPIPANIHHCmPo1AwY5pkUGcpVL3W-uHyWEn4vbgzp34Qw","rawId":"SNBSJTt1DHEuG9XBd6lfc4XXqxkppWfFbt4P5sRVQEPIPANIHHCmPo1AwY5pkUGcpVL3W+uHyWEn4vbgzp34Qw==","response":{"clientDataJSON":"eyJjaGFsbGVuZ2UiOiJtY1BYSURSSFNQQkYyZ0pXVTU4R1ByUjNUb2RMRFhSMWtISmhnVmFuWW5VIiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDo5MDAwIiwidHlwZSI6IndlYmF1dGhuLmdldCJ9","authenticatorData":"SZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2MBAAAABA==","signature":"MEUCIQCWGnyWIV4s13/9TRcLtDesxa0UJs+pwNaF3YDP/5RHDwIgIWlEiH74R7sPiyNffp8Tof3qo1s8jVvFDxCGejlICFI=","userHandle":""},"type":"public-key"}`,
}

var attestationPublicKeys = []string{
	`-----BEGIN CERTIFICATE-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEwzIpvM5A6mZQXYxRIhfp0sb/21yT
cr/sp5Y5DU0IWODQf5ldS2rlDCl62yEaQDM9Akxbsay/vA/S5ut4VSsvoA==
-----END CERTIFICATE-----`,
	`-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAELxxTguKmjCV4N5OMqd2Sl9AIxSlt
aPevmQxSqnyNlAfEHOaQDaZ6pC2gC+Z0KS4Ln/XQiJp0X1BmTd+K+FdqSg==
-----END PUBLIC KEY-----`,
}
