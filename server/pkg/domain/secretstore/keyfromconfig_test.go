package secretstore

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"testing"
)

// Every key format configuration validation accepts (64 hex, 44 base64, 32
// raw characters) gives the same 32 bytes here, and they build an encryptor.
// A base64 key used to arrive as 44 raw bytes and stop the API at start-up.
func TestKeyFromConfig_EveryAcceptedFormat(t *testing.T) {
	raw := bytes.Repeat([]byte{0xA5}, 32)
	cases := map[string]string{
		"hex":    hex.EncodeToString(raw),
		"base64": base64.StdEncoding.EncodeToString(raw),
	}
	for name, v := range cases {
		got := KeyFromConfig(v)
		if !bytes.Equal(got, raw) {
			t.Fatalf("%s: key = %x, want %x", name, got, raw)
		}
		if _, err := NewEncryptor(got); err != nil {
			t.Fatalf("%s: NewEncryptor: %v", name, err)
		}
	}
	rawKey := "0123456789abcdefghijklmnopqrstuv" // 32 raw characters
	if got := KeyFromConfig(rawKey); string(got) != rawKey {
		t.Fatalf("raw: key = %q", got)
	}
	// A value of no accepted shape is passed through and refused.
	if _, err := NewEncryptor(KeyFromConfig("too-short")); err == nil {
		t.Fatal("NewEncryptor accepted a 9-byte key")
	}
}
