package app

import (
	"fmt"
	"strings"

	"github.com/openctemio/api/pkg/crypto"
)

// APIKeyEncryptionService handles encryption and decryption of tenant API keys.
type APIKeyEncryptionService struct {
	encryptor crypto.Encryptor
}

// NewAPIKeyEncryptionService creates a new APIKeyEncryptionService.
// If encryptor is nil, a NoOpEncryptor is used (for development only).
func NewAPIKeyEncryptionService(encryptor crypto.Encryptor) *APIKeyEncryptionService {
	if encryptor == nil {
		encryptor = crypto.NewNoOpEncryptor()
	}
	return &APIKeyEncryptionService{encryptor: encryptor}
}

// EncryptAPIKey encrypts an API key for secure storage.
// Returns a prefixed string to identify encrypted values: "enc:v1:<ciphertext>"
func (s *APIKeyEncryptionService) EncryptAPIKey(plainKey string) (string, error) {
	if plainKey == "" {
		return "", nil
	}

	encrypted, err := s.encryptor.EncryptString(plainKey)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt API key: %w", err)
	}

	// Prefix with version for future-proofing
	return "enc:v1:" + encrypted, nil
}

// DecryptAPIKey decrypts an API key from storage.
// If the key is not encrypted (no prefix), returns it as-is (backward compatibility).
func (s *APIKeyEncryptionService) DecryptAPIKey(encryptedKey string) (string, error) {
	if encryptedKey == "" {
		return "", nil
	}

	// Check for encryption prefix
	if !strings.HasPrefix(encryptedKey, "enc:v1:") {
		// Not encrypted (legacy key), return as-is
		// This allows backward compatibility during migration
		return encryptedKey, nil
	}

	// Remove prefix and decrypt
	ciphertext := strings.TrimPrefix(encryptedKey, "enc:v1:")
	plaintext, err := s.encryptor.DecryptString(ciphertext)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt API key: %w", err)
	}

	return plaintext, nil
}

// IsEncrypted checks if an API key is already encrypted.
func (s *APIKeyEncryptionService) IsEncrypted(key string) bool {
	return strings.HasPrefix(key, "enc:v1:")
}

// MaskAPIKey returns a masked version of an API key for logging/display.
// Shows first 4 and last 4 characters: "sk-ab...xyz"
func MaskAPIKey(key string) string {
	if key == "" {
		return ""
	}

	// Handle encrypted keys
	if strings.HasPrefix(key, "enc:v1:") {
		return "[encrypted]"
	}

	// Mask plaintext keys
	if len(key) <= 12 {
		return strings.Repeat("*", len(key))
	}

	return key[:4] + "..." + key[len(key)-4:]
}
