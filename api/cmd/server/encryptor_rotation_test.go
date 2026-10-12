package main

import (
	"testing"

	"github.com/openctemio/openctem/api/internal/config"
	"github.com/openctemio/openctem/api/pkg/crypto"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// With APP_ENCRYPTION_KEY_PREVIOUS set the server encrypts with the new key
// and still reads values written under the old one, so it can start on the
// new key before cmd/rekey has run.
func TestInitEncryptor_PreviousKeys(t *testing.T) {
	const oldKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	const newKey = "ab00112233445566778899aabbccddeeff00112233445566778899aabbccddee"
	oldC, _ := crypto.NewCipherFromKey(oldKey, "")
	underOld, _ := oldC.EncryptString("stored before the rotation")

	cfg := &config.Config{Encryption: config.EncryptionConfig{Key: newKey, KeyFormat: "hex", PreviousKeys: []string{oldKey}}}
	enc, err := initEncryptor(cfg, logger.NewNop())
	if err != nil {
		t.Fatalf("initEncryptor: %v", err)
	}
	if got, err := enc.DecryptString(underOld); err != nil || got != "stored before the rotation" {
		t.Fatalf("old value must stay readable: %q %v", got, err)
	}
	fresh, _ := enc.EncryptString("new")
	if _, err := oldC.DecryptString(fresh); err == nil {
		t.Fatal("new values must be encrypted with the new key")
	}

	cfg.Encryption.PreviousKeys = nil
	plain, err := initEncryptor(cfg, logger.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := plain.DecryptString(underOld); err == nil {
		t.Fatal("without the previous key the old value must not be readable")
	}
}
