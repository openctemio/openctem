package ticketing

import (
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

func titledFinding(t *testing.T, src vulnerability.FindingSource, title string) *vulnerability.Finding {
	t.Helper()
	f, err := vulnerability.NewFinding(shared.NewID(), shared.NewID(), src, "nuclei", vulnerability.SeverityHigh, title)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// Two issues of one title on two hosts make two issue titles.
func TestIssueTitle_NamesTheTarget(t *testing.T) {
	f := titledFinding(t, vulnerability.FindingSourceDAST, "CVE-2019-9516 in nginx 1.15.5")
	f.SetTitle("CVE-2019-9516 in nginx 1.15.5")
	f.SetNetwork(vulnerability.NetworkLocation{Port: 443, Transport: "tcp"})
	a := issueTitle(f, "10.20.30.41")
	b := issueTitle(f, "edge-01.shop.example.com")
	if a != "[high] CVE-2019-9516 in nginx 1.15.5 on 10.20.30.41:443" {
		t.Fatalf("a: %q", a)
	}
	if a == b {
		t.Fatal("two assets, one title")
	}
}

// An asset name is scanner-supplied: it cannot add a line or a direction
// override to a title, and the title stays inside GitHub's 256 runes.
func TestIssueTitle_HostileAssetName(t *testing.T) {
	f := titledFinding(t, vulnerability.FindingSourceDAST, "x")
	got := issueTitle(f, "host\r\nInjected: 1\u202E"+strings.Repeat("h", 600))
	if strings.ContainsAny(got, "\r\n\u202E") {
		t.Fatalf("control characters kept: %q", got)
	}
	if n := len([]rune(got)); n > 256 {
		t.Fatalf("%d runes", n)
	}
}

// A secret finding's URL can carry the secret itself: the target is the
// asset only, never the URL.
func TestOutboundTarget_SecretUsesNoURL(t *testing.T) {
	f := titledFinding(t, vulnerability.FindingSourceSecret, "AWS key")
	f.SetLocation("https://portal.example.com/?key=AKIAEXAMPLE", 0, 0, 0, 0)
	if got := OutboundTarget(f, "portal.example.com"); got != "portal.example.com" {
		t.Fatalf("got %q", got)
	}
	d := titledFinding(t, vulnerability.FindingSourceDAST, "Exposed .git")
	d.SetLocation("https://portal.example.com/.git/config", 0, 0, 0, 0)
	if got := OutboundTarget(d, "portal.example.com"); got != "https://portal.example.com/.git/config" {
		t.Fatalf("full content keeps the URL: %q", got)
	}
}
