package assetgroup

import (
	"errors"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestParsePaste_Kinds(t *testing.T) {
	text := strings.Join([]string{
		"# comment", "", "  WWW.Example.COM.  ", "api.example.com", "10.0.0.5", "::ffff:10.0.0.6",
		"10.1.2.3/16", "https://Example.com:443/Login", "http://example.com:8080", "2001:db8::1",
		"www.example.com", // duplicate of the first
	}, "\r\n")
	items, rejected, err := ParsePaste(text)
	if err != nil {
		t.Fatal(err)
	}
	if len(rejected) != 0 {
		t.Fatalf("rejected %+v", rejected)
	}
	want := []PasteItem{
		{Line: 3, Kind: PasteDomain, Value: "www.example.com"},
		{Line: 4, Kind: PasteDomain, Value: "api.example.com"},
		{Line: 5, Kind: PasteIP, Value: "10.0.0.5"},
		{Line: 6, Kind: PasteIP, Value: "10.0.0.6"},
		{Line: 7, Kind: PasteCIDR, Value: "10.1.0.0/16"},
		{Line: 8, Kind: PasteURL, Value: "https://example.com/Login"},
		{Line: 9, Kind: PasteURL, Value: "http://example.com:8080"},
		{Line: 10, Kind: PasteIP, Value: "2001:db8::1"},
	}
	if len(items) != len(want) {
		t.Fatalf("items %+v", items)
	}
	for i := range want {
		if items[i] != want[i] {
			t.Errorf("item %d = %+v, want %+v", i, items[i], want[i])
		}
	}
}

func TestParsePaste_RejectsHostileAndMalformedLines(t *testing.T) {
	hostile := map[string]string{
		"javascript:alert(1)":          ReasonNotAValue,
		"JaVaScRiPt://x":               ReasonScheme,
		"data:text/html,x":             ReasonNotAValue,
		"ftp://example.com":            ReasonScheme,
		"file:///etc/passwd":           ReasonScheme,
		"https://user:pw@example.com/": ReasonUserInfo,
		"https://":                     ReasonBadHost,
		"https://exa mple.com":         ReasonSpacesInValue,
		"example.com\rinjected":        ReasonControlChars,
		"exam\x00ple.com":              ReasonControlChars,
		"two words":                    ReasonSpacesInValue,
		"0.0.0.0/0":                    ReasonBroadRange,
		"10.0.0.0/7":                   ReasonBroadRange,
		"2001:db8::/16":                ReasonBroadRange,
		"10.0.0.1/33":                  ReasonBadRange,
		"*.example.com":                ReasonNotAValue,
		"localhost":                    ReasonNotAValue,
		"-x.example.com":               ReasonNotAValue,
		"https://" + strings.Repeat("a", 3000) + ".com": ReasonTooLong,
	}
	for line, reason := range hostile {
		items, rejected, err := ParsePaste(line)
		if err != nil {
			t.Fatalf("%q: %v", line, err)
		}
		if len(items) != 0 || len(rejected) != 1 {
			t.Errorf("%q: accepted %+v / rejected %+v", line, items, rejected)
			continue
		}
		if rejected[0].Reason != reason {
			t.Errorf("%q: reason %q, want %q", line, rejected[0].Reason, reason)
		}
		if strings.ContainsAny(rejected[0].Value, "\r\n\x00") || len(rejected[0].Value) > 40 {
			t.Errorf("%q: echoed value %q is not safe", line, rejected[0].Value)
		}
	}
}

func TestParsePaste_LineCap(t *testing.T) {
	ok := strings.Repeat("a.example.com\n", MaxPasteLines-1) + "z.example.com"
	if _, _, err := ParsePaste(ok); err != nil {
		t.Fatalf("a list of %d lines: %v", MaxPasteLines, err)
	}
	tooMany := strings.Repeat("a.example.com\n", MaxPasteLines) + "z.example.com"
	_, _, err := ParsePaste(tooMany)
	if err == nil || !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("a list over the cap: %v", err)
	}
}
