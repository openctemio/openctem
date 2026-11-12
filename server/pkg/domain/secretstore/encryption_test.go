package secretstore

import (
	"bytes"
	"errors"
	"testing"
)

func TestEncryptor_PreviousKeysDecrypt(t *testing.T) {
	oldKey := bytes.Repeat([]byte{1}, 32)
	newKey := bytes.Repeat([]byte{2}, 32)
	oldEnc, _ := NewEncryptor(oldKey)
	sealed, err := oldEnc.Encrypt([]byte("secret"))
	if err != nil {
		t.Fatal(err)
	}

	onlyNew, _ := NewEncryptor(newKey)
	if _, err := onlyNew.Decrypt(sealed); !errors.Is(err, ErrDecryptionFailed) {
		t.Fatalf("new key alone must not open old ciphertext, got %v", err)
	}
	ring, err := NewEncryptor(newKey, oldKey)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := ring.Decrypt(sealed); err != nil || string(got) != "secret" {
		t.Fatalf("previous key must open old ciphertext: %q %v", got, err)
	}
	fresh, _ := ring.Encrypt([]byte("x"))
	if _, err := oldEnc.Decrypt(fresh); err == nil {
		t.Fatal("new values must be sealed with the current key")
	}
	if _, err := NewEncryptor(newKey, []byte("short")); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("a bad previous key must be refused, got %v", err)
	}
}

func TestKeyFromConfig(t *testing.T) {
	hexKey := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	if b := KeyFromConfig(hexKey); len(b) != 32 {
		t.Fatalf("hex key must decode to 32 bytes, got %d", len(b))
	}
	raw := "abcdefghijklmnopqrstuvwxyz012345"
	if b := KeyFromConfig(raw); string(b) != raw {
		t.Fatal("a non-hex key is used as raw bytes")
	}
}
