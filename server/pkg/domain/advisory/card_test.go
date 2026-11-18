package advisory

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func fixture(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile("testdata/OCA-2026-9001.json")
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func decodeFixture(t *testing.T) *Card {
	t.Helper()
	c, err := Decode(fixture(t))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestDecodeFixture(t *testing.T) {
	c := decodeFixture(t)
	if !IsCardID(c.ID) || c.ExploitationStatus() != ExploitPoCPublic || len(c.VulnIDs()) != 2 || c.Withdrawn() {
		t.Fatalf("%+v", c)
	}
	// Forward compatible: an unknown field is ignored, an unknown predicate
	// reads as "other" (it cannot narrow).
	if got := c.Affected[1].Conditions[0].Predicate; got != "other" {
		t.Fatalf("unknown predicate kept as %q", got)
	}
	keys := c.ProductKeys()
	if len(keys) != 2 || keys[0] != (ProductKey{"a", "example", "examplehttpd"}) {
		t.Fatalf("%+v", keys)
	}
}

func TestMatchVersion(t *testing.T) {
	c := decodeFixture(t)
	const p, plus = "a:example:examplehttpd", "a:example:examplehttpd_plus"
	cases := []struct {
		key, v string
		want   VersionMatch
	}{
		{p, "0.6.17", VersionNotAffected},
		{p, "1.9.4", VersionAffected}, // only the second statement covers it
		{p, "1.9.5", VersionAffected},
		{p, "2.4.8", VersionAffected},
		{p, "2.4.9", VersionNotAffected},
		{p, "2.5.1", VersionAffected},
		{p, "2.5.2", VersionNotAffected},
		{p, "0.7.0", VersionAffected}, // the second statement's range
		{p, "", VersionUnknown},
		{plus, "9.9.9", VersionUnknown}, // versions not published yet
		{"a:example:other", "1.0", VersionNotAffected},
	}
	for _, tc := range cases {
		if got := c.MatchVersion(tc.key, tc.v); got != tc.want {
			t.Errorf("%s %s: %v, want %v", tc.key, tc.v, got, tc.want)
		}
	}
}

func TestDecodeRefusals(t *testing.T) {
	cases := map[string]func(m map[string]any){
		"in review":          func(m map[string]any) { m["review"].(map[string]any)["state"] = "in_review" },
		"two person by self": func(m map[string]any) { m["review"].(map[string]any)["reviewed_by"] = "author1" },
		"markup in title":    func(m map[string]any) { m["title"] = "x <img src=x onerror=alert(1)>" },
		"bidi in summary":    func(m map[string]any) { m["summary"] = "ok \u202e evil" },
		"javascript link":    func(m map[string]any) { m["poc"].([]any)[0].(map[string]any)["url"] = "javascript:alert(1)" },
		"http source":        func(m map[string]any) { m["sources"].([]any)[0].(map[string]any)["url"] = "http://example.com/" },
		"bad id":             func(m map[string]any) { m["id"] = "CVE-2026-1" },
		"wrong schema":       func(m map[string]any) { m["schema"] = "openctem.advisory-card/v2" },
		"uncited workaround": func(m map[string]any) { m["workarounds"].([]any)[0].(map[string]any)["sources"] = []any{} },
		"unknown exploit":    func(m map[string]any) { m["exploitation"].(map[string]any)["status"] = "guessed" },
		"bad version": func(m map[string]any) {
			m["affected"].([]any)[0].(map[string]any)["ranges"].([]any)[0].(map[string]any)["fixed"] = "2.4.9;x"
		},
		"withdrawn no reason": func(m map[string]any) { m["review"].(map[string]any)["state"] = "withdrawn" },
		"long title":          func(m map[string]any) { m["title"] = strings.Repeat("x", 161) },
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			var m map[string]any
			if err := json.Unmarshal(fixture(t), &m); err != nil {
				t.Fatal(err)
			}
			mut(m)
			raw, _ := json.Marshal(m)
			if _, err := Decode(raw); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	if _, err := Decode(make([]byte, MaxCardBytes+1)); err == nil {
		t.Fatal("oversized card accepted")
	}
}

func TestExploitation(t *testing.T) {
	if ExploitNone.PublicExploit() || !ExploitPoCPublic.PublicExploit() || !ExploitVendorConfirmed.PublicExploit() ||
		Exploitation("bogus").PublicExploit() || Exploitation("").PublicExploit() {
		t.Fatal("PublicExploit")
	}
	if Stronger(ExploitWeaponised, ExploitPoCPublic) != ExploitWeaponised || Stronger("", ExploitInTheWild) != ExploitInTheWild {
		t.Fatal("Stronger")
	}
}
