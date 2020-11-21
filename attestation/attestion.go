// attestation can be imported to import all supported attestation formats
package attestation

import (
	_ "github.com/koesie10/webauthn/attestation/androidsafetynet"
	_ "github.com/koesie10/webauthn/attestation/fido"
	_ "github.com/koesie10/webauthn/attestation/none"
	_ "github.com/koesie10/webauthn/attestation/packed"
)
