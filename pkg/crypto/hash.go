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
// SECURITY NOTE on CodeQL go/weak-cryptographic-algorithm:
//
// CodeQL flags this function because a parameter literally named "token"
// feeding into SHA-256 matches its password-hashing-with-weak-algorithm
// rule. That rule exists because user-chosen PASSWORDS are low-entropy
// and need a computationally expensive KDF (bcrypt, argon2, pbkdf2) to
// slow offline brute force. This function is NOT used for passwords —
// OpenCTEM passwords go through bcrypt via pkg/password. HashToken only
// ever sees:
//
//   - API keys: 32 bytes from crypto/rand (256 bits of entropy)
//   - Agent bootstrap tokens: similar high-entropy random
//   - Session tokens: 32 bytes crypto/rand
//
// At 256 bits of entropy, an attacker with a leaked hash would need
// ~2^255 SHA-256 evaluations on average to brute-force. No KDF slows
// that further than the input space already does — a slow KDF on a
// cryptographically-random 256-bit input is cargo-cult.
//
// F-9: This unkeyed hash is retained only for backward compatibility
// with pre-existing rows in the DB. NEW writes should use
// HashTokenPeppered (HMAC-SHA256 with a server-side pepper) so that a
// DB-only leak cannot be brute-forced via rainbow table — see
// agent/service.go hashAgentAPIKey for the canonical caller.
//
// Action for reviewers: dismiss the CodeQL alert as
// "Won't fix — false positive; input is cryptographically random,
// not a password".
func HashToken(token string) string {
	// #nosec G401 — SHA-256 is intentional; see doc-comment.
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

// HashTokenBytes returns the SHA256 hash of a token as bytes.
// See HashToken's doc-comment for the CodeQL false-positive rationale;
// same applies here.
func HashTokenBytes(token string) []byte {
	// #nosec G401 — see HashToken.
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
