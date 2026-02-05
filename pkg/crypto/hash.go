package crypto

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
)

// HashToken returns the SHA256 hash of a token as a hex string.
// This is used for secure token storage (bootstrap tokens, API keys, etc.).
// The original token should never be stored; only its hash should be persisted.
func HashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

// HashTokenBytes returns the SHA256 hash of a token as bytes.
func HashTokenBytes(token string) []byte {
	hash := sha256.Sum256([]byte(token))
	return hash[:]
}

// VerifyTokenHash checks if a plaintext token matches a stored hash.
// This uses constant-time comparison to prevent timing attacks.
func VerifyTokenHash(token, storedHash string) bool {
	computedHash := HashToken(token)
	// Use crypto/subtle for constant-time comparison to prevent timing attacks.
	// This is the standard library's secure implementation.
	return subtle.ConstantTimeCompare([]byte(computedHash), []byte(storedHash)) == 1
}
