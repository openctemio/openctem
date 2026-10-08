// Package secretstore provides public types and helpers reusable across the codebase.
package secretstore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/openctemio/openctem/api/pkg/crypto"
)

var (
	// ErrInvalidKey is returned when the encryption key is invalid.
	ErrInvalidKey = errors.New("encryption key must be 32 bytes for AES-256")
	// ErrDecryptionFailed is returned when decryption fails.
	ErrDecryptionFailed = errors.New("failed to decrypt credential data")
	// ErrInvalidCiphertext is returned when the ciphertext is too short.
	ErrInvalidCiphertext = errors.New("ciphertext too short")
)

// Encryptor handles credential encryption and decryption.
type Encryptor struct {
	key []byte
	// previous keys still decrypt (key rotation, APP_ENCRYPTION_KEY_PREVIOUS);
	// nothing is encrypted with them.
	previous [][]byte
}

// NewEncryptor creates a new Encryptor with the given 32-byte key. previous
// are earlier keys whose ciphertexts must stay readable during a rotation.
func NewEncryptor(key []byte, previous ...[]byte) (*Encryptor, error) {
	if len(key) != 32 {
		return nil, ErrInvalidKey
	}
	for _, p := range previous {
		if len(p) != 32 {
			return nil, ErrInvalidKey
		}
	}
	return &Encryptor{key: key, previous: previous}, nil
}

// KeyFromConfig returns the secret-store key bytes for an APP_ENCRYPTION_KEY
// value, decoded exactly as configuration validation and the credentials
// cipher decode it (crypto.ParseKey: 64 hex, 44 base64 or 32 raw
// characters). A base64 key used to reach the secret store as its 44 raw
// bytes, and the API refused to start with a key the configuration accepted.
// A value ParseKey refuses is returned as is, so NewEncryptor reports it.
func KeyFromConfig(key string) []byte {
	if b, err := crypto.ParseKey(key, ""); err == nil {
		return b
	}
	return []byte(key)
}

// Encrypt encrypts the given data using AES-256-GCM.
func (e *Encryptor) Encrypt(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(e.key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Prepend nonce to ciphertext
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// Decrypt decrypts the given ciphertext using AES-256-GCM, with the current
// key first and then each previous key.
func (e *Encryptor) Decrypt(ciphertext []byte) ([]byte, error) {
	out, err := decryptWith(e.key, ciphertext)
	if err == nil || !errors.Is(err, ErrDecryptionFailed) {
		return out, err
	}
	for _, p := range e.previous {
		if out, perr := decryptWith(p, ciphertext); perr == nil {
			return out, nil
		}
	}
	return nil, err
}

func decryptWith(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, ErrInvalidCiphertext
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	return plaintext, nil
}

// EncryptJSON encrypts a struct as JSON.
func (e *Encryptor) EncryptJSON(data any) ([]byte, error) {
	plaintext, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal data: %w", err)
	}
	return e.Encrypt(plaintext)
}

// DecryptJSON decrypts ciphertext and unmarshals to the given struct.
func (e *Encryptor) DecryptJSON(ciphertext []byte, dest any) error {
	plaintext, err := e.Decrypt(ciphertext)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(plaintext, dest); err != nil {
		return fmt.Errorf("failed to unmarshal data: %w", err)
	}
	return nil
}
