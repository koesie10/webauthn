package protocol

// AttestationFormatFunction will be called when checking whether an Attestation is valid.
type AttestationFormatFunction func(Attestation, []byte) error

var attestationFormats = make(map[string]AttestationFormatFunction)

// RegisterFormat will register an attestation format. If the name already exists, it will be overwritten without
// warning.
func RegisterFormat(name string, f AttestationFormatFunction) {
	attestationFormats[name] = f
}
