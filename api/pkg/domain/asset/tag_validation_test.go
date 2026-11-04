package asset

import (
	"strings"
	"testing"
)

// Every writer adds tags through AddTag, so it is the backstop of the shared
// tag validator: a hostile tag never lands on an asset, whatever the path.
func TestAddTag_RefusesWhatTheValidatorRefuses(t *testing.T) {
	a, err := NewAsset("h.example.com", AssetTypeHost, CriticalityMedium)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{
		strings.Repeat("a", MaxTagLength+1), "a‮b", "<b>x</b>", "=1+1", "bug-bounty", "sys:owner", "program:x", "  ",
	} {
		a.AddTag(bad)
	}
	if len(a.Tags()) != 0 {
		t.Fatalf("refused tags were stored: %v", a.Tags())
	}
	a.AddTag("  team:payments ")
	a.AddTag("team:payments")
	if got := a.Tags(); len(got) != 1 || got[0] != "team:payments" {
		t.Fatalf("a valid tag is stored normalized, once: %v", got)
	}
}
