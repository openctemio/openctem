package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

func TestCipher_EncryptDecrypt(t *testing.T) {
	// Generate a random 32-byte key
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	cipher, err := NewCipher(key)
	if err != nil {
		t.Fatalf("failed to create cipher: %v", err)
	}

	tests := []struct {
		name      string
		plaintext string
	}{
		{"empty string", ""},
		{"simple string", "hello world"},
		{"special chars", "!@#$%^&*()_+-=[]{}|;':\",./<>?"},
		{"unicode", "こんにちは世界 🔐"},
		{"long string", strings.Repeat("a", 10000)},
		{"json", `{"api_key": "ghp_xxxx", "secret": "abc123"}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encrypted, err := cipher.EncryptString(tt.plaintext)
			if err != nil {
				t.Fatalf("failed to encrypt: %v", err)
			}

			// Verify encrypted is valid base64
			if _, err := base64.StdEncoding.DecodeString(encrypted); err != nil {
				t.Fatalf("encrypted output is not valid base64: %v", err)
			}

			// Verify encrypted is different from plaintext (unless empty)
			if len(tt.plaintext) > 0 && encrypted == tt.plaintext {
				t.Fatal("encrypted output matches plaintext")
			}

			decrypted, err := cipher.DecryptString(encrypted)
			if err != nil {
				t.Fatalf("failed to decrypt: %v", err)
			}

			if decrypted != tt.plaintext {
				t.Fatalf("decrypted text doesn't match: got %q, want %q", decrypted, tt.plaintext)
			}
		})
	}
}

func TestCipher_DifferentCiphertextEachTime(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	cipher, err := NewCipher(key)
	if err != nil {
		t.Fatalf("failed to create cipher: %v", err)
	}

	plaintext := "same plaintext"
	encrypted1, _ := cipher.EncryptString(plaintext)
	encrypted2, _ := cipher.EncryptString(plaintext)

	if encrypted1 == encrypted2 {
		t.Fatal("encrypting same plaintext twice should produce different ciphertext (random nonce)")
	}

	// But both should decrypt to the same value
	decrypted1, _ := cipher.DecryptString(encrypted1)
	decrypted2, _ := cipher.DecryptString(encrypted2)

	if decrypted1 != decrypted2 || decrypted1 != plaintext {
		t.Fatal("decrypted values should match original plaintext")
	}
}

func TestCipher_InvalidKey(t *testing.T) {
	tests := []struct {
		name    string
		keyLen  int
		wantErr bool
	}{
		{"too short", 16, true},
		{"too long", 64, true},
		{"valid 32 bytes", 32, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := make([]byte, tt.keyLen)
			_, err := NewCipher(key)
			if (err != nil) != tt.wantErr {
				t.Fatalf("NewCipher() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCipher_FromHex(t *testing.T) {
	// Generate a key and encode to hex
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	hexKey := hex.EncodeToString(key)

	cipher, err := NewCipherFromHex(hexKey)
	if err != nil {
		t.Fatalf("failed to create cipher from hex: %v", err)
	}

	plaintext := "test message"
	encrypted, err := cipher.EncryptString(plaintext)
	if err != nil {
		t.Fatalf("failed to encrypt: %v", err)
	}

	decrypted, err := cipher.DecryptString(encrypted)
	if err != nil {
		t.Fatalf("failed to decrypt: %v", err)
	}

	if decrypted != plaintext {
		t.Fatalf("decrypted text doesn't match: got %q, want %q", decrypted, plaintext)
	}
}

func TestCipher_FromBase64(t *testing.T) {
	// Generate a key and encode to base64
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	b64Key := base64.StdEncoding.EncodeToString(key)

	cipher, err := NewCipherFromBase64(b64Key)
	if err != nil {
		t.Fatalf("failed to create cipher from base64: %v", err)
	}

	plaintext := "test message"
	encrypted, err := cipher.EncryptString(plaintext)
	if err != nil {
		t.Fatalf("failed to encrypt: %v", err)
	}

	decrypted, err := cipher.DecryptString(encrypted)
	if err != nil {
		t.Fatalf("failed to decrypt: %v", err)
	}

	if decrypted != plaintext {
		t.Fatalf("decrypted text doesn't match: got %q, want %q", decrypted, plaintext)
	}
}

func TestCipher_DecryptInvalidCiphertext(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	cipher, err := NewCipher(key)
	if err != nil {
		t.Fatalf("failed to create cipher: %v", err)
	}

	tests := []struct {
		name       string
		ciphertext string
		wantErr    error
	}{
		{"invalid base64", "not-valid-base64!!!", ErrInvalidCiphertext},
		{"too short", base64.StdEncoding.EncodeToString([]byte("short")), ErrInvalidCiphertext},
		{"corrupted", base64.StdEncoding.EncodeToString(make([]byte, 50)), ErrDecryptionFailed},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := cipher.DecryptString(tt.ciphertext)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

func TestCipher_WrongKey(t *testing.T) {
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	rand.Read(key1)
	rand.Read(key2)

	cipher1, _ := NewCipher(key1)
	cipher2, _ := NewCipher(key2)

	encrypted, _ := cipher1.EncryptString("secret data")

	// Trying to decrypt with a different key should fail
	_, err := cipher2.DecryptString(encrypted)
	if err == nil {
		t.Fatal("decrypting with wrong key should fail")
	}
}

func BenchmarkCipher_Encrypt(b *testing.B) {
	key := make([]byte, 32)
	rand.Read(key)
	cipher, _ := NewCipher(key)
	plaintext := "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = cipher.EncryptString(plaintext)
	}
}

func BenchmarkCipher_Decrypt(b *testing.B) {
	key := make([]byte, 32)
	rand.Read(key)
	cipher, _ := NewCipher(key)
	encrypted, _ := cipher.EncryptString("ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = cipher.DecryptString(encrypted)
	}
}
