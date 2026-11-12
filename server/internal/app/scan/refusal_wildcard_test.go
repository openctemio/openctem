package scan

import (
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
)

// A wildcard-only name is refused with its own code, a message and the
// review fix, never as "no scope entry" (its entry exists).
func TestRefusalCodeForState_WildcardOnly(t *testing.T) {
	code := RefusalCodeForState(attribution.StateWildcardOnly)
	if code != scopedom.RefusalWildcardOnly {
		t.Fatalf("code = %q, want %q", code, scopedom.RefusalWildcardOnly)
	}
	r := scopedom.NewRefusal("guess.example.com", code, nil, 0)
	if r.Message == "" {
		t.Fatal("no message")
	}
	if len(r.Fixes) != 1 || r.Fixes[0].Action != scopedom.FixReviewAsset {
		t.Fatalf("fixes = %+v, want review the asset", r.Fixes)
	}
}
