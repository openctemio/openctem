package secretstore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
}

// NewEncryptor creates a new Encryptor with the given 32-byte key.
func NewEncryptor(key []byte) (*Encryptor, error) {
	if len(key) != 32 {
		return nil, ErrInvalidKey
	}
	return &Encryptor{key: key}, nil
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

// Decrypt decrypts the given ciphertext using AES-256-GCM.
func (e *Encryptor) Decrypt(ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(e.key)
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
