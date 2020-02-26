package fido_test

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
	`{"publicKey":{"rp":{"name":"accountsvc"},"user":{"id":"MTAwNjg1ODU4NDE3ODI5NDc4NA==","name":"Koen Vlaswinkel","displayName":"Koen Vlaswinkel"},"pubKeyCredParams":[{"type":"public-key","alg":-7}],"timeout":10000,"attestation":"direct","challenge":"+1jQysnwaIjNU+GrwRp4PWNBMlX0i9/caRkcKd7LPj8="}}`,
	`{"publicKey":{"rp":{"name":"webauthn-demo"},"user":{"name":"koen","id":"a29lbg==","displayName":"koen"},"challenge":"2HzAlPIGskbn53hBJZeH3kZ6XfcHWMnzbATVG/FSgkI=","pubKeyCredParams":[{"type":"public-key","alg":-7}],"timeout":30000,"authenticatorSelection":{"requireResidentKey":false},"attestation":"direct"}}`,
}

var attestationResponses = []string{
	`{"id":"LOXI3xfiLvIP04MD_S2ZmJYwn3cvMX1FUXxiQO7xlfUvrfcj99UVO2aMrMAwsGvsujY7NHWiM6G3B6ryKJDBBdab-cl4tVZeOwOMhgvHLXk","rawId":"LOXI3xfiLvIP04MD/S2ZmJYwn3cvMX1FUXxiQO7xlfUvrfcj99UVO2aMrMAwsGvsujY7NHWiM6G3B6ryKJDBBdab+cl4tVZeOwOMhgvHLXk=","response":{"attestationObject":"o2dhdHRTdG10omNzaWdYRjBEAiAJ8Q7i8DQzKlb00g4Wby4PoEjlI+s3bS+kVKI3PKoyXQIgDzcP2c5vpplZdmftN+zUDNfXtG1TniWbJv2+6kGZ8bljeDVjgVkBKzCCAScwgc6gAwIBAgIBADAKBggqhkjOPQQDAjAWMRQwEgYDVQQDDAtLcnlwdG9uIEtleTAeFw0xODA5MTcxODQ3NDJaFw0yODA5MTcxODQ3NDJaMBYxFDASBgNVBAMMC0tyeXB0b24gS2V5MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEwzIpvM5A6mZQXYxRIhfp0sb/21yTcr/sp5Y5DU0IWODQf5ldS2rlDCl62yEaQDM9Akxbsay/vA/S5ut4VSsvoKMNMAswCQYDVR0TBAIwADAKBggqhkjOPQQDAgNIADBFAiA4Yx+5MtKVnjme6V3qXKQ2qcgaHfO6DMgXM9kwOCZcNAIhAJdNk5PPSA04ITfrX9HQy5azo8sH9yhkW7c6gLdb/Kz+aGF1dGhEYXRhWNRJlg3liA6MaHQ0Fw9kdmBbj+SuuaKGMseZXPO6gx2XY0EAAAAALOXI3xfiLvIP04MD/S2ZmABQLOXI3xfiLvIP04MD/S2ZmJYwn3cvMX1FUXxiQO7xlfUvrfcj99UVO2aMrMAwsGvsujY7NHWiM6G3B6ryKJDBBdab+cl4tVZeOwOMhgvHLXmlAQIDJiABIVggwzIpvM5A6mZQXYxRIhfp0sb/21yTcr/sp5Y5DU0IWOAiWCDQf5ldS2rlDCl62yEaQDM9Akxbsay/vA/S5ut4VSsvoGNmbXRoZmlkby11MmY=","clientDataJSON":"eyJjaGFsbGVuZ2UiOiItMWpReXNud2FJak5VLUdyd1JwNFBXTkJNbFgwaTlfY2FSa2NLZDdMUGo4IiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDo1Mzg3OSIsInRva2VuQmluZGluZyI6eyJzdGF0dXMiOiJub3Qtc3VwcG9ydGVkIn0sInR5cGUiOiJ3ZWJhdXRobi5jcmVhdGUifQ=="},"type":"public-key"}`,
	`{"id":"EBT1LOefp-8ID0n2jchlyaPrKcWZ6jdHH8nb0Z-hi9JHsOpTpCNUbJ7ijJOKdetLOy2cqdxNq8zkWYmCgpapKg","rawId":"EBT1LOefp+8ID0n2jchlyaPrKcWZ6jdHH8nb0Z+hi9JHsOpTpCNUbJ7ijJOKdetLOy2cqdxNq8zkWYmCgpapKg==","response":{"attestationObject":"o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEgwRgIhAJkpVpWsMm/Z1OnF/+B/juq/IAlKqhakms5HkNf6ZKLWAiEAm2qNX/bHUkkdaJ0seanz5xxVDCn+bKGEPyQP3ZpPczNjeDVjgVkCUzCCAk8wggE3oAMCAQICBA0ACxYwDQYJKoZIhvcNAQELBQAwLjEsMCoGA1UEAxMjWXViaWNvIFUyRiBSb290IENBIFNlcmlhbCA0NTcyMDA2MzEwIBcNMTQwODAxMDAwMDAwWhgPMjA1MDA5MDQwMDAwMDBaMDExLzAtBgNVBAMMJll1YmljbyBVMkYgRUUgU2VyaWFsIDIzOTI1NzM0MDE1NzY1MjcwMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAETKz6btEEuhlL1uBm1+E/zGpgDxDSSFx+o9vUTNDVDbJROHujvR665t7mJQoFWMbpvmEYpEOOWkNfHtLrDOi7haM7MDkwIgYJKwYBBAGCxAoCBBUxLjMuNi4xLjQuMS40MTQ4Mi4xLjUwEwYLKwYBBAGC5RwCAQEEBAMCBSAwDQYJKoZIhvcNAQELBQADggEBAI7CTaiBlYLnMIQZnJ8UCvrqgFuin80CTT4UAiGWsBwh0eY+CRSwL4LEFZITkLlFYyOsfMDlI7oddSN/Jmn8HzrPWvzKVP/+mCuRMSdz735wFNYX5xle+NLkoctZjyHOCqdd4B8lgX0nzwNiPZuf+sdY5fhzhLRmtbpfBDToTP57tLR5WlIY6kJ6QKecpZ5sVNxCzSVxRncAptZV7YSsX2we05Kt5mHkBHqhi5CTPQQmOObHov7cB+4q5CpufDzEBFTKPL3tWxV6HvQr0J6Mp6bZFICq5nTP7VPatnnJelRA9VmPSpQuLjpRqpJFKRobj8eQ9yuveXG/7uutBOzBHW9oYXV0aERhdGFYxEmWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjQQAAAAAAAAAAAAAAAAAAAAAAAAAAAEAQFPUs55+n7wgPSfaNyGXJo+spxZnqN0cfydvRn6GL0kew6lOkI1RsnuKMk4p160s7LZyp3E2rzORZiYKClqkqpQECAyYgASFYIF6oiA6H+mU150XH7WJ2vnzNmdzgr5YloPao7ePjNjlOIlggg0f3u4CtxsBkkKjo7v4luyJui9tJ1rGTBF3YkYlcADo=","clientDataJSON":"eyJjaGFsbGVuZ2UiOiIySHpBbFBJR3NrYm41M2hCSlplSDNrWjZYZmNIV01uemJBVFZHX0ZTZ2tJIiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDo5MDAwIiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9"},"type":"public-key"}`,
}
