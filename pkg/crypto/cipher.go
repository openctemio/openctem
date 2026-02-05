// Package crypto provides encryption utilities for sensitive data.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

// Encryptor provides encryption and decryption capabilities.
type Encryptor interface {
	// EncryptString encrypts plaintext and returns base64-encoded ciphertext.
	EncryptString(plaintext string) (string, error)
	// DecryptString decrypts base64-encoded ciphertext and returns plaintext.
	DecryptString(encoded string) (string, error)
}

// NoOpEncryptor is an Encryptor that does not encrypt (for development/testing).
type NoOpEncryptor struct{}

// EncryptString returns the plaintext as-is (no encryption).
func (n *NoOpEncryptor) EncryptString(plaintext string) (string, error) {
	return plaintext, nil
}

// DecryptString returns the encoded string as-is (no decryption).
func (n *NoOpEncryptor) DecryptString(encoded string) (string, error) {
	return encoded, nil
}

// NewNoOpEncryptor creates a no-op encryptor for development/testing.
func NewNoOpEncryptor() Encryptor {
	return &NoOpEncryptor{}
}

var (
	// ErrInvalidKey is returned when the encryption key is invalid.
	ErrInvalidKey = errors.New("crypto: invalid encryption key")
	// ErrInvalidCiphertext is returned when the ciphertext is malformed.
	ErrInvalidCiphertext = errors.New("crypto: invalid ciphertext")
	// ErrDecryptionFailed is returned when decryption fails.
	ErrDecryptionFailed = errors.New("crypto: decryption failed")
)

// Cipher provides AES-256-GCM encryption and decryption.
type Cipher struct {
	aead cipher.AEAD
}

// Ensure Cipher implements Encryptor interface.
var _ Encryptor = (*Cipher)(nil)

// NewCipher creates a new Cipher with the given key.
// The key must be exactly 32 bytes for AES-256.
func NewCipher(key []byte) (*Cipher, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("%w: key must be exactly 32 bytes, got %d", ErrInvalidKey, len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidKey, err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto: failed to create GCM cipher: %w", err)
	}

	return &Cipher{aead: aead}, nil
}

// NewCipherFromHex creates a new Cipher from a hex-encoded key.
func NewCipherFromHex(hexKey string) (*Cipher, error) {
	key, err := hexDecode(hexKey)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid hex key: %v", ErrInvalidKey, err)
	}
	return NewCipher(key)
}

// NewCipherFromBase64 creates a new Cipher from a base64-encoded key.
func NewCipherFromBase64(b64Key string) (*Cipher, error) {
	key, err := base64.StdEncoding.DecodeString(b64Key)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid base64 key: %v", ErrInvalidKey, err)
	}
	return NewCipher(key)
}

// Encrypt encrypts plaintext and returns base64-encoded ciphertext.
// The ciphertext includes the nonce prepended to it.
func (c *Cipher) Encrypt(plaintext []byte) (string, error) {
	// Generate a random nonce
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("crypto: failed to generate nonce: %w", err)
	}

	// Encrypt and prepend nonce
	ciphertext := c.aead.Seal(nonce, nonce, plaintext, nil)

	// Return base64-encoded result
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// EncryptString encrypts a string and returns base64-encoded ciphertext.
func (c *Cipher) EncryptString(plaintext string) (string, error) {
	return c.Encrypt([]byte(plaintext))
}

// Decrypt decrypts base64-encoded ciphertext and returns plaintext.
func (c *Cipher) Decrypt(encoded string) ([]byte, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid base64: %v", ErrInvalidCiphertext, err)
	}

	nonceSize := c.aead.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("%w: ciphertext too short", ErrInvalidCiphertext)
	}

	// Extract nonce and actual ciphertext
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	// Decrypt
	plaintext, err := c.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	return plaintext, nil
}

// DecryptString decrypts base64-encoded ciphertext and returns a string.
func (c *Cipher) DecryptString(encoded string) (string, error) {
	plaintext, err := c.Decrypt(encoded)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

// hexDecode decodes a hex string to bytes.
func hexDecode(s string) ([]byte, error) {
	if len(s)%2 != 0 {
		return nil, errors.New("odd length hex string")
	}

	result := make([]byte, len(s)/2)
	for i := 0; i < len(s); i += 2 {
		high, ok1 := hexCharToByte(s[i])
		low, ok2 := hexCharToByte(s[i+1])
		if !ok1 || !ok2 {
			return nil, errors.New("invalid hex character")
		}
		result[i/2] = high<<4 | low
	}
	return result, nil
}

func hexCharToByte(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	default:
		return 0, false
	}
}
