package handler

import (
	"regexp"
	"testing"
)

func TestGenerateETag(t *testing.T) {
	perms := []string{"assets:read", "findings:read"}
	etag := generateETag(perms, 3)

	// Quoted, version-prefixed, 8 bytes of SHA-256 in hex.
	if !regexp.MustCompile(`^"v3-[0-9a-f]{16}"$`).MatchString(etag) {
		t.Fatalf("unexpected ETag format %q", etag)
	}
	// sha256("assets:read,findings:read,3")[:8]
	if want := `"v3-17078daf1a664027"`; etag != want {
		t.Fatalf("ETag = %s, want %s", etag, want)
	}
	if generateETag(perms, 3) != etag {
		t.Fatal("ETag must be deterministic")
	}
	if generateETag(perms, 4) == etag {
		t.Fatal("a version bump must change the ETag")
	}
	if generateETag([]string{"assets:read"}, 3) == etag {
		t.Fatal("a permission change must change the ETag")
	}
}
