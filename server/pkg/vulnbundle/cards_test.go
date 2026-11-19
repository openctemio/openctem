package vulnbundle

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/openctemio/openctem/server/pkg/domain/advisory"
)

func cardLine(t testing.TB, id string) string {
	t.Helper()
	raw, err := os.ReadFile("../domain/advisory/testdata/OCA-2026-9001.json")
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := json.Compact(&buf, raw); err != nil {
		t.Fatal(err)
	}
	return strings.Replace(buf.String(), "OCA-2026-9001", id, 1)
}

func cardsStream(t *testing.T, lines ...string) ([]byte, *IntelStream) {
	gz, s := intelGz(t, IntelStreamCards, lines...)
	s.Version = advisory.Schema
	return gz, s
}

func TestParseIntelCards(t *testing.T) {
	gz, s := cardsStream(t, cardLine(t, "OCA-2026-9001"), cardLine(t, "OCA-2026-9002"))
	got, err := ParseIntelCards(gz, s)
	if err != nil || len(got) != 2 || got[1].ID != "OCA-2026-9002" || got[0].ExploitationStatus() != advisory.ExploitPoCPublic {
		t.Fatal(got, err)
	}
}

func TestParseIntelCardsRefusals(t *testing.T) {
	a, b := cardLine(t, "OCA-2026-9001"), cardLine(t, "OCA-2026-9002")
	cases := map[string]struct {
		lines []string
		mut   func(*IntelStream)
	}{
		"unordered":      {[]string{b, a}, nil},
		"duplicate":      {[]string{a, a}, nil},
		"in review":      {[]string{strings.Replace(a, `"state":"reviewed"`, `"state":"in_review"`, 1)}, nil},
		"markup":         {[]string{strings.Replace(a, `"title":"examplehttpd:`, `"title":"<script>`, 1)}, nil},
		"other format":   {[]string{a}, func(s *IntelStream) { s.Version = "openctem.advisory-card/v2" }},
		"more than said": {[]string{a, b}, func(s *IntelStream) { s.File.Records = 1 }},
		"hash":           {[]string{a}, func(s *IntelStream) { s.File.SHA256 = strings.Repeat("0", 64) }},
		"over the cap":   {[]string{a}, func(s *IntelStream) { s.File.Records = advisory.MaxCards + 1 }},
		"not json":       {[]string{"{"}, nil},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			gz, s := cardsStream(t, c.lines...)
			if c.mut != nil {
				c.mut(s)
			}
			if _, err := ParseIntelCards(gz, s); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

// FuzzParseIntelCards: any cards file under a manifest that matches it
// either parses into valid, ordered cards or is refused, never a panic.
func FuzzParseIntelCards(f *testing.F) {
	f.Add(cardLine(f, "OCA-2026-9001"))
	f.Add(strings.Replace(cardLine(f, "OCA-2026-9002"), `"state":"reviewed"`, `"state":"withdrawn","withdrawn_reason":"Retracted."`, 1))
	f.Add(`{"schema":"openctem.advisory-card/v1"}`)
	f.Fuzz(func(t *testing.T, body string) {
		lines := strings.Split(body, "\n")
		gz, s := cardsStream(t, lines...)
		got, err := ParseIntelCards(gz, s)
		if err != nil {
			return
		}
		for i, c := range got {
			if c.Validate() != nil || (i > 0 && got[i-1].ID >= c.ID) {
				t.Fatal("parsed an invalid or unordered card")
			}
		}
	})
}
