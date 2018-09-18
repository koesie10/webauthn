package protocol

import "crypto/rand"

// ChallengeSize represents the size of a challenge created by NewChallenge.
const ChallengeSize = 32

// Challenge represents a challenge. It is defined as a separate type to make it clear that NewChallenge should
// be used to create it.
type Challenge []byte

// NewChallenge creates a new cryptographically secure random challenge of ChallengeSize bytes.
func NewChallenge() (Challenge, error) {
	b := make([]byte, ChallengeSize)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}
