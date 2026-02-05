package scannertemplate

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

// Signer handles template signing and verification.
type Signer struct {
	secret []byte
}

// NewSigner creates a new Signer with the given secret key.
func NewSigner(secret []byte) *Signer {
	return &Signer{secret: secret}
}

// Sign computes the HMAC-SHA256 signature of content.
func (s *Signer) Sign(content []byte) string {
	h := hmac.New(sha256.New, s.secret)
	h.Write(content)
	return hex.EncodeToString(h.Sum(nil))
}

// Verify verifies that the given signature matches the expected signature.
func (s *Signer) Verify(content []byte, signature string) bool {
	expected := s.Sign(content)
	return hmac.Equal([]byte(expected), []byte(signature))
}

// ComputeSignature computes the HMAC-SHA256 signature of content using the provided secret.
func ComputeSignature(content []byte, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write(content)
	return hex.EncodeToString(h.Sum(nil))
}

// VerifySignature verifies that the given signature matches the expected signature for the content.
func VerifySignature(content []byte, secret, signature string) bool {
	expected := ComputeSignature(content, secret)
	return hmac.Equal([]byte(expected), []byte(signature))
}

// ComputeHash computes the SHA256 hash of the content.
func ComputeHash(content []byte) string {
	hash := sha256.Sum256(content)
	return hex.EncodeToString(hash[:])
}
