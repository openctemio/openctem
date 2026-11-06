package password

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/crypto"
)

// Set-password, reset and verification tokens go into links; a trailing "="
// is cut by some mail clients and chat tools, so the tokens carry no padding.
func TestTokensHaveNoPadding(t *testing.T) {
	for name, gen := range map[string]func() (string, error){
		"reset":        GenerateResetToken,
		"verification": GenerateVerificationToken,
	} {
		for range 50 {
			tok, err := gen()
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			if strings.Contains(tok, "=") || len(tok) != 43 {
				t.Fatalf("%s token %q: want 43 characters and no '='", name, tok)
			}
			raw, err := base64.RawURLEncoding.DecodeString(tok)
			if err != nil || len(raw) != 32 {
				t.Fatalf("%s token %q: not 32 bytes of unpadded URL-safe base64 (%v)", name, tok, err)
			}
		}
	}
}

// Tokens are stored as the hash of the string as given, so a padded token
// issued before this change still matches its stored hash, and the unpadded
// form of it does not (nothing maps one onto the other).
func TestPaddedTokenStillVerifies(t *testing.T) {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(i * 7)
	}
	padded := base64.URLEncoding.EncodeToString(raw)
	if !strings.HasSuffix(padded, "=") {
		t.Fatalf("fixture %q should be padded", padded)
	}
	stored := crypto.HashToken(padded)
	if crypto.HashToken(padded) != stored {
		t.Fatal("a padded token no longer matches its stored hash")
	}
	if crypto.HashToken(strings.TrimRight(padded, "=")) == stored {
		t.Fatal("the unpadded form must be a different token")
	}
}
