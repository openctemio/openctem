package releasefeed

import (
	"crypto/ed25519"
	"encoding/hex"
	"testing"
)

// A build with no pinned key verifies nothing, so the version check and the
// release feed import stay inert in every install: refuse to ship that.
func TestPinnedKeysShipped(t *testing.T) {
	if len(PinnedKeys) == 0 {
		t.Fatal("no release feed key is pinned")
	}
	if len(PinnedKeys) > MaxPinnedKeys {
		t.Fatalf("%d keys pinned, at most %d", len(PinnedKeys), MaxPinnedKeys)
	}
	seen := map[string]bool{}
	for _, k := range PinnedKeys {
		b, err := hex.DecodeString(k)
		if err != nil || len(b) != ed25519.PublicKeySize {
			t.Fatalf("pinned key %q is not a %d-byte hex Ed25519 public key", k, ed25519.PublicKeySize)
		}
		if seen[k] {
			t.Fatalf("pinned key %q listed twice", k)
		}
		seen[k] = true
	}
}
