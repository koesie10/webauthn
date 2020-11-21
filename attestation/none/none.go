// none implements the None (WebAuthn spec section 8.7) attestation statement format
package none

import "github.com/koesie10/webauthn/protocol"

func init() {
	protocol.RegisterFormat("none", verifyNoneFormat)
}

func verifyNoneFormat(a protocol.Attestation, clientDataHash []byte) error {
	if len(a.AttStmt) > 0 {
		return protocol.ErrInvalidAttestation.WithDebug("invalid attStmt for 'none' attestation")
	}

	return nil
}
