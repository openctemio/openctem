package jira

import (
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// hostileFinding carries Jira wiki markup a scan target controls: a disguised
// link, a user mention, a tracking image, an HTML macro, a {noformat} breakout
// and an RLO override (Trojan Source) in the title, path and description.
func hostileFinding(t *testing.T) *vulnerability.Finding {
	t.Helper()
	f, err := vulnerability.NewFinding(shared.NewID(), shared.NewID(),
		vulnerability.FindingSourceDAST, "nuclei", vulnerability.SeverityHigh, "x")
	if err != nil {
		t.Fatalf("NewFinding: %v", err)
	}
	f.SetTitle("Login [Re-authenticate|https://evil.test/login] [~admin] \u202Egnp.exe")
	f.SetLocation("src/{html}<b>x</b>{html}/!https://evil.test/p.png!", 7, 7, 0, 0)
	f.SetDescription("Banner: {noformat}\nh1. Pay here\n[Click|https://evil.test/pay]\n{html}<script>alert(1)</script>{html}\nhttps://evil.test/raw")
	return f
}

func TestTicketDescription_ScannerTextCannotInjectWikiMarkup(t *testing.T) {
	desc := ticketDescription(hostileFinding(t))

	for _, bad := range []string{
		"[Re-authenticate|", "[~admin]", "!https://evil.test/p.png!", "{html}<b>",
		"https://evil.test", "\u202E",
	} {
		if strings.Contains(desc, bad) {
			t.Errorf("description contains raw %q:\n%s", bad, desc)
		}
	}
	// The scanner description sits in exactly one {noformat} block that it
	// cannot close: two tags in the whole description, one opening and one
	// closing.
	if n := strings.Count(strings.ToLower(desc), "{noformat}"); n != 2 {
		t.Errorf("want exactly one {noformat} block, found %d tags:\n%s", n, desc)
	}
	if !strings.Contains(desc, `\[Re\-authenticate\|https\[:\]//evil.test/login\]`) {
		t.Errorf("title not escaped as expected:\n%s", desc)
	}
	if !strings.Contains(desc, "*Location:* src/\\{html\\}") {
		t.Errorf("location not escaped as expected:\n%s", desc)
	}
}

func TestTicketSummary_PlainOneLineCapped(t *testing.T) {
	f := hostileFinding(t)
	f.SetTitle("multi\nline \u202Etitle " + strings.Repeat("a", 400))
	got := ticketSummary(f)
	if strings.ContainsAny(got, "\n\u202E") {
		t.Fatalf("summary keeps newline or bidi control: %q", got)
	}
	if n := len([]rune(got)); n > 255 {
		t.Fatalf("summary is %d runes, Jira allows 255", n)
	}
	if !strings.HasPrefix(got, "[high] multi line title") {
		t.Fatalf("summary = %q", got)
	}
}
