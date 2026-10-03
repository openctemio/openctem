package ticketing

import (
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// hostileFinding carries GitHub markdown a scan target controls: a disguised
// link, a tracking image, raw HTML, @mentions, an issue-closing reference, a
// code-fence breakout and an RLO override (Trojan Source).
func hostileFinding(t *testing.T) *vulnerability.Finding {
	t.Helper()
	f, err := vulnerability.NewFinding(shared.NewID(), shared.NewID(),
		vulnerability.FindingSourceDAST, "nuclei", vulnerability.SeverityHigh, "x")
	if err != nil {
		t.Fatalf("NewFinding: %v", err)
	}
	f.SetTitle("XSS @octocat [login](https://evil.test) \u202Egnp.exe\nsecond line")
	f.SetLocation("src/`<img src=x>`/[a](https://evil.test).go", 3, 3, 0, 0)
	f.SetDescription("```\n</code><details open>[Click to fix](https://evil.test/pay)" +
		"\n![pixel](https://evil.test/p.png)\ncc @org/security-team, closes #1\n```\nafter")
	return f
}

func TestBuildIssueBody_ScannerTextIsCodeOnly(t *testing.T) {
	body := buildIssueBody(hostileFinding(t))

	// Location: one code span whose fence the path cannot close.
	const locationSpan = "**Location:** `` src/`<img src=x>`/[a](https://evil.test).go:3 ``"
	if !strings.Contains(body, locationSpan) {
		t.Errorf("location not in a code span:\n%s", body)
	}
	// Description: one fenced block, longer than the ``` inside it.
	start := strings.Index(body, "````text\n")
	end := strings.LastIndex(body, "\n````")
	if start < 0 || end <= start {
		t.Fatalf("description not in a ```` fence:\n%s", body)
	}
	outside := strings.Replace(body[:start]+body[end+len("\n````"):], locationSpan, "", 1)
	for _, bad := range []string{"](https://", "<details", "<img", "@octocat", "@org/", "#1", "\u202E"} {
		if strings.Contains(outside, bad) {
			t.Errorf("markup %q outside a code span/block:\n%s", bad, outside)
		}
	}
	if strings.Contains(body, "\u202E") {
		t.Errorf("bidi control kept:\n%s", body)
	}
}

func TestIssueTitle_PlainOneLineCapped(t *testing.T) {
	f := hostileFinding(t)
	got := issueTitle(f)
	if strings.ContainsAny(got, "\n\u202E") {
		t.Fatalf("title keeps newline or bidi control: %q", got)
	}
	f.SetTitle(strings.Repeat("a", 400))
	if n := len([]rune(issueTitle(f))); n > 256 {
		t.Fatalf("title is %d runes, GitHub allows 256", n)
	}
}
