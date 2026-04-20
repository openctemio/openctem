package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
)

// HashToken returns the SHA256 hash of a token as a hex string.
// This is used for secure token storage (bootstrap tokens, API keys, etc.).
// The original token should never be stored; only its hash should be persisted.
//
// F-9: This unkeyed hash is retained only for backward compatibility with
// pre-existing hashes in the database. NEW API-key writes should use
// HashTokenPeppered instead, which adds HMAC with a server-side pepper so
// an attacker who exfiltrates the database but not the pepper cannot
// brute-force the raw keys offline.
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

// HashTokenPeppered returns HMAC-SHA256(pepper, token) as a lowercase hex
// string. When `pepper` is empty, the function falls back to the plain
// SHA-256 (HashToken) behaviour so callers that do not yet have a pepper
// configured still produce a stable, deterministic hash.
//
// F-9: use this for any new API-key persistence. The pepper should be the
// platform-wide APP_ENCRYPTION_KEY (or a dedicated secret derived from it).
// Because the output is deterministic, existing unique-index lookups keep
// working. Because the pepper lives in application config (not the DB), a
// database-only leak no longer yields material that can be brute-forced
// with generic rainbow tables / hashcat against leaked `key_hash` columns.
func HashTokenPeppered(token, pepper string) string {
	if pepper == "" {
		return HashToken(token)
	}
	mac := hmac.New(sha256.New, []byte(pepper))
	_, _ = mac.Write([]byte(token))
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifyTokenHashAny checks a raw token against a stored hash using either
// the peppered (HMAC-SHA256) variant OR the legacy plain SHA-256 variant.
// Callers that cannot yet re-hash every row on write use this to keep old
// rows working while new writes produce peppered hashes.
//
// Both comparisons use constant-time compare to avoid timing leaks. If
// `pepper` is empty the peppered branch is skipped.
func VerifyTokenHashAny(token, storedHash, pepper string) bool {
	if pepper != "" {
		peppered := HashTokenPeppered(token, pepper)
		if subtle.ConstantTimeCompare([]byte(peppered), []byte(storedHash)) == 1 {
			return true
		}
	}
	legacy := HashToken(token)
	return subtle.ConstantTimeCompare([]byte(legacy), []byte(storedHash)) == 1
}
