package advisory

import (
	"bytes"
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
		"line separator":      func(m map[string]any) { m["title"] = "x\u2028Patch now" },
		"paragraph separator": func(m map[string]any) { m["summary"] = "x\u2029Patch now" },
		"link in title":       func(m map[string]any) { m["title"] = "Patch now at https://evil.example" },
		"www in a note":       func(m map[string]any) { m["severity"].(map[string]any)["note"] = "see www.evil.example" },
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

// seedCards are a reviewed and a withdrawn card with links, workarounds and
// detection ideas, so the fuzzer starts on the review and list paths.
func seedCards(t testing.TB) [][]byte {
	raw, err := os.ReadFile("testdata/OCA-2026-9001.json")
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	reviewed, _ := json.Marshal(m)
	r := m["review"].(map[string]any)
	r["state"], r["withdrawn_reason"] = "withdrawn", "The vendor retracted the advisory."
	withdrawn, _ := json.Marshal(m)
	return [][]byte{reviewed, withdrawn, reportedCard(t)}
}

func reportedCard(t testing.TB) []byte {
	raw, err := os.ReadFile("testdata/OCA-2026-9001.json")
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	m["review"] = map[string]any{"state": "reported", "author": "author1"}
	out, _ := json.Marshal(m)
	return out
}

// FuzzDecode: the lenient platform decoder never panics, and a card it
// accepts encodes back to a card it accepts with the same content.
func FuzzDecode(f *testing.F) {
	for _, b := range seedCards(f) {
		f.Add(b)
	}
	f.Add([]byte(`{"schema":"openctem.advisory-card/v1"}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		c, err := Decode(b)
		if err != nil {
			return
		}
		again, err := json.Marshal(c)
		if err != nil {
			t.Fatal(err)
		}
		back, err := Decode(again)
		if err != nil {
			t.Fatalf("re-encoded card refused: %v", err)
		}
		if b2, _ := json.Marshal(back); !bytes.Equal(again, b2) {
			t.Fatal("round trip changed the card")
		}
	})
}

func TestSeedCardsDecode(t *testing.T) {
	for _, b := range seedCards(t) {
		if _, err := Decode(b); err != nil {
			t.Fatal(err)
		}
	}
}

func TestReportedCard(t *testing.T) {
	c, err := Decode(reportedCard(t))
	if err != nil || !c.Reported() || c.Withdrawn() {
		t.Fatal(c, err)
	}
	cases := map[string]func(m map[string]any){
		"names a reviewer": func(m map[string]any) { m["review"].(map[string]any)["reviewed_by"] = "reviewer1" },
		"names a mode":     func(m map[string]any) { m["review"].(map[string]any)["mode"] = "two_person" },
		"exploitation from a blog only": func(m map[string]any) {
			m["sources"] = append(m["sources"].([]any), map[string]any{"id": "blog", "url": "https://example.org/b",
				"publisher": "Blog", "tier": "researcher", "title": "b", "retrieved_at": "2026-11-18T18:00:00Z"})
			m["exploitation"].(map[string]any)["sources"] = []any{"blog"}
		},
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			var m map[string]any
			if err := json.Unmarshal(reportedCard(t), &m); err != nil {
				t.Fatal(err)
			}
			mut(m)
			raw, _ := json.Marshal(m)
			if _, err := Decode(raw); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

// At an equal revision only a withdrawal of a standing card is applied: a
// withdrawn card never comes back without a higher revision.
func TestSupersedes(t *testing.T) {
	card := func(rev int, state string) *Card { return &Card{Revision: rev, Review: Review{State: state}} }
	cases := []struct {
		heldRev   int
		heldState string
		in        *Card
		want      bool
	}{
		{1, StateReviewed, card(2, StateReviewed), true},
		{1, StateReviewed, card(1, StateWithdrawn), true},
		{1, StateReported, card(1, StateWithdrawn), true},
		{1, StateWithdrawn, card(1, StateReviewed), false},
		{1, StateWithdrawn, card(1, StateReported), false},
		{1, StateReported, card(1, StateReviewed), false},
		{1, StateReviewed, card(1, StateReviewed), false},
		{2, StateReviewed, card(1, StateWithdrawn), false},
		{1, StateWithdrawn, card(2, StateReviewed), true},
		{1, StateWithdrawn, card(2, StateReported), false},
		{1, StateReviewed, card(2, StateReported), false},
		{1, StateReported, card(2, StateReported), true},
		{1, StateReported, card(2, StateReviewed), true},
	}
	for _, c := range cases {
		if got := Supersedes(c.heldRev, c.heldState, c.in); got != c.want {
			t.Fatalf("held r%d %s, in r%d %s: %v, want %v", c.heldRev, c.heldState, c.in.Revision, c.in.Review.State, got, c.want)
		}
	}
}
