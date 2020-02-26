package packed_test

import (
	"encoding/json"
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

var attestationRequests = []string{
	`{"publicKey":{"rp":{"name":"webauthn-demo"},"user":{"name":"koen","id":"a29lbg==","displayName":"koen"},"challenge":"JUtlYcgpkSiFNzsThDYuOrtSVY1VeLofM+mWTRCCXqU=","pubKeyCredParams":[{"type":"public-key","alg":-7}],"timeout":30000,"authenticatorSelection":{"requireResidentKey":false},"attestation":"direct"}}`,
}

var attestationResponses = []string{
	`{"id":"SNBSJTt1DHEuG9XBd6lfc4XXqxkppWfFbt4P5sRVQEPIPANIHHCmPo1AwY5pkUGcpVL3W-uHyWEn4vbgzp34Qw","rawId":"SNBSJTt1DHEuG9XBd6lfc4XXqxkppWfFbt4P5sRVQEPIPANIHHCmPo1AwY5pkUGcpVL3W+uHyWEn4vbgzp34Qw==","response":{"attestationObject":"o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEcwRQIgFls/elhmdZmqEBEKafdcyvQPDrTdBRMW92v6RKJj1bACIQCZ+46sXn65dMEpPuGxvMUruV5i7XN25ctFV/iAi3wSomN4NWOBWQLCMIICvjCCAaagAwIBAgIEdIb9wjANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowbzELMAkGA1UEBhMCU0UxEjAQBgNVBAoMCVl1YmljbyBBQjEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjEoMCYGA1UEAwwfWXViaWNvIFUyRiBFRSBTZXJpYWwgMTk1NTAwMzg0MjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJVd8633JH0xde/9nMTzGk6HjrrhgQlWYVD7OIsuX2Unv1dAmqWBpQ0KxS8YRFwKE1SKE1PIpOWacE5SO8BN6+2jbDBqMCIGCSsGAQQBgsQKAgQVMS4zLjYuMS40LjEuNDE0ODIuMS4xMBMGCysGAQQBguUcAgEBBAQDAgUgMCEGCysGAQQBguUcAQEEBBIEEPigEfOMCk0VgAYXER+e3H0wDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAQEAMVxIgOaaUn44Zom9af0KqG9J655OhUVBVW+q0As6AIod3AH5bHb2aDYakeIyyBCnnGMHTJtuekbrHbXYXERIn4aKdkPSKlyGLsA/A+WEi+OAfXrNVfjhrh7iE6xzq0sg4/vVJoywe4eAJx0fS+Dl3axzTTpYl71Nc7p/NX6iCMmdik0pAuYJegBcTckE3AoYEg4K99AM/JaaKIblsbFh8+3LxnemeNf7UwOczaGGvjS6UzGVI0Odf9lKcPIwYhuTxM5CaNMXTZQ7xq4/yTfC3kPWtE4hFT34UJJflZBiLrxG4OsYxkHw/n5vKgmpspB3GfYuYTWhkDKiE8CYtyg87mhhdXRoRGF0YVjESZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2NBAAAAA/igEfOMCk0VgAYXER+e3H0AQEjQUiU7dQxxLhvVwXepX3OF16sZKaVnxW7eD+bEVUBDyDwDSBxwpj6NQMGOaZFBnKVS91vrh8lhJ+L24M6d+EOlAQIDJiABIVggLxxTguKmjCV4N5OMqd2Sl9AIxSltaPevmQxSqnyNlAciWCDEHOaQDaZ6pC2gC+Z0KS4Ln/XQiJp0X1BmTd+K+FdqSg==","clientDataJSON":"eyJjaGFsbGVuZ2UiOiJKVXRsWWNncGtTaUZOenNUaERZdU9ydFNWWTFWZUxvZk0tbVdUUkNDWHFVIiwibmV3X2tleXNfbWF5X2JlX2FkZGVkX2hlcmUiOiJkbyBub3QgY29tcGFyZSBjbGllbnREYXRhSlNPTiBhZ2FpbnN0IGEgdGVtcGxhdGUuIFNlZSBodHRwczovL2dvby5nbC95YWJQZXgiLCJvcmlnaW4iOiJodHRwOi8vbG9jYWxob3N0OjkwMDAiLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0="},"type":"public-key"}`,
}
