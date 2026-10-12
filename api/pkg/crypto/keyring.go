package crypto

import (
	"encoding/base64"
	"errors"
	"fmt"
)

// ParseKey decodes an encryption key written the way APP_ENCRYPTION_KEY is:
// format "hex" (64 characters), "base64" (44 characters) or "raw" (32 bytes).
// An empty format is detected from the length, as the server configuration
// does. It returns the 32 key bytes.
func ParseKey(key, format string) ([]byte, error) {
	if format == "" {
		switch len(key) {
		case 64:
			format = "hex"
		case 44:
			format = "base64"
		case 32:
			format = "raw"
		default:
			return nil, fmt.Errorf("%w: length %d (expected 32 raw, 64 hex or 44 base64)", ErrInvalidKey, len(key))
		}
	}
	var b []byte
	var err error
	switch format {
	case "hex":
		b, err = hexDecode(key)
	case "base64":
		b, err = base64.StdEncoding.DecodeString(key)
	case "raw":
		b = []byte(key)
	default:
		return nil, fmt.Errorf("%w: unknown key format %q", ErrInvalidKey, format)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: invalid %s key: %v", ErrInvalidKey, format, err)
	}
	if len(b) != 32 {
		return nil, fmt.Errorf("%w: key must be exactly 32 bytes, got %d", ErrInvalidKey, len(b))
	}
	return b, nil
}

// NewCipherFromKey builds a Cipher from an APP_ENCRYPTION_KEY-style value
// (see ParseKey).
func NewCipherFromKey(key, format string) (*Cipher, error) {
	b, err := ParseKey(key, format)
	if err != nil {
		return nil, err
	}
	return NewCipher(b)
}

// KeyRing is an Encryptor for key rotation: it always encrypts with the
// current key and decrypts with the current key first, then each previous
// key. While APP_ENCRYPTION_KEY_PREVIOUS lists the old key, values written
// under it stay readable, so the server can start on a new key before the
// stored values are re-encrypted (cmd/rekey).
type KeyRing struct {
	current  *Cipher
	previous []*Cipher
}

var _ Encryptor = (*KeyRing)(nil)

// NewKeyRing returns an Encryptor over current and previous keys.
func NewKeyRing(current *Cipher, previous ...*Cipher) *KeyRing {
	return &KeyRing{current: current, previous: previous}
}

// EncryptString encrypts with the current key.
func (k *KeyRing) EncryptString(plaintext string) (string, error) {
	return k.current.EncryptString(plaintext)
}

// DecryptString decrypts with the current key, then each previous key.
func (k *KeyRing) DecryptString(encoded string) (string, error) {
	out, err := k.current.DecryptString(encoded)
	if err == nil || !errors.Is(err, ErrDecryptionFailed) {
		return out, err
	}
	for _, p := range k.previous {
		if out, perr := p.DecryptString(encoded); perr == nil {
			return out, nil
		}
	}
	return "", err
}
