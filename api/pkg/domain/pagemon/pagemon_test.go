package pagemon

import (
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestNormalizeURL(t *testing.T) {
	ok := map[string]string{
		"HTTPS://App.Example.com:443/login#x": "https://app.example.com/login",
		"http://example.com":                  "http://example.com/",
		"https://example.com:8443/a?b=1":      "https://example.com:8443/a?b=1",
	}
	for in, want := range ok {
		got, err := NormalizeURL(in)
		if err != nil || got != want {
			t.Errorf("NormalizeURL(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"", "ftp://x/", "https://user:pw@x.com/", "/relative", "javascript:alert(1)", "https://" + strings.Repeat("a", 3000)} {
		if _, err := NormalizeURL(in); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("NormalizeURL(%q) accepted", in)
		}
	}
	if got := OriginName("https://app.example.com/login"); got != "https://app.example.com" {
		t.Errorf("origin %q", got)
	}
}

func TestIgnorePatternsAndCadence(t *testing.T) {
	if _, err := NormalizeIgnorePatterns([]string{"("}); err == nil {
		t.Error("invalid regex accepted")
	}
	if _, err := NormalizeIgnorePatterns([]string{strings.Repeat("a", 201)}); err == nil {
		t.Error("long pattern accepted")
	}
	many := make([]string, 11)
	for i := range many {
		many[i] = strings.Repeat("x", i+1)
	}
	if _, err := NormalizeIgnorePatterns(many); err == nil {
		t.Error("11 patterns accepted")
	}
	if got, _ := NormalizeIgnorePatterns([]string{" a ", "a", ""}); len(got) != 1 {
		t.Errorf("dedupe: %v", got)
	}
	for _, h := range []int{1, 5, 169} {
		if _, err := NormalizeCadence(h); err == nil {
			t.Errorf("cadence %d accepted", h)
		}
	}
	if h, _ := NormalizeCadence(0); h != DefaultCadenceHours {
		t.Error("default cadence")
	}
}

func TestNormalizeCapture_Hostile(t *testing.T) {
	now := time.Date(2026, 10, 31, 9, 0, 0, 0, time.UTC)
	big := strings.Repeat("é", MaxBodyBytes) // 2 bytes each
	c, err := Normalize(map[string]any{
		"url": "https://app.example.com/", "final_url": "https://evil.example.net/", "status_code": float64(200),
		"content_type": "text/html\r\nX: y", "size": float64(-3), "sha256": "nothex", "body": big + "\xff",
		"fetched_at": "2099-01-01T00:00:00Z",
	}, "httpx", now)
	if err != nil {
		t.Fatal(err)
	}
	if c.FinalURL != "" {
		t.Error("final URL on another host kept")
	}
	if strings.ContainsAny(c.ContentType, "\r\n") || c.Size != 0 || c.SHA256 != "" {
		t.Errorf("fields not cleaned: %+v", c.ContentType)
	}
	if len(c.Body) > MaxBodyBytes || !c.BodyTruncated || !strings.HasSuffix(c.Body, "é") {
		t.Errorf("body cap: %d %v", len(c.Body), c.BodyTruncated)
	}
	if !c.FetchedAt.Equal(now) {
		t.Error("future fetched_at kept")
	}
	if _, err := Normalize(map[string]any{"url": "file:///etc/passwd"}, "", now); err == nil {
		t.Error("file URL accepted")
	}
	budget := 10
	out, skipped := FromProperty([]any{map[string]any{"url": "https://a.example/", "body": "0123456789abc"}, "junk"}, "x", now, &budget)
	if len(out) != 1 || skipped != 1 || out[0].Body != "" || !out[0].BodyTruncated {
		t.Errorf("budget: %+v %d", out, skipped)
	}
}

func TestScriptIdentity(t *testing.T) {
	cases := map[string]string{
		"https://cdn.example.com/app.3f9a1c7e.js?v=12":         "//cdn.example.com/app.*.js",
		"https://cdn.example.com/static/js/main-a1b2c3d4e5.js": "//cdn.example.com/static/js/main-*.js",
		"https://x.example/lib.js?b=2&a=1&_=99":                "//x.example/lib.js?a=1&b=2",
		"https://x.example/jquery.min.js":                      "//x.example/jquery.min.js",
	}
	for in, want := range cases {
		u, _ := url.Parse(in)
		if got := ScriptIdentity(u); got != want {
			t.Errorf("ScriptIdentity(%s) = %s; want %s", in, got, want)
		}
	}
}

const pageV1 = `<html><head>
<script src="/static/app.11aa22bb.js"></script>
<script src="https://cdn.example.com/lib.js" integrity="sha384-x"></script>
<script nonce="r4nd0mN0nc3V4lu3xyz">window.csrf="AbCdEf0123456789AbCdEf";</script>
<style>body{}</style></head><body><h1>Sign in</h1><p>Updated 20261031</p>
<template><p>hidden</p></template></body></html>`

const pageV2 = `<html><head>
<script src="/static/app.99ff88ee.js"></script>
<script src="https://cdn.example.com/lib.js" integrity="sha384-x"></script>
<script src="https://evil-skimmer.example.net/s.js"></script>
<script nonce="0therN0nceV4lu3abc">window.csrf="ZyXwVu9876543210ZyXwVu";</script>
<style>body{color:red}</style></head><body><h1>Sign in now</h1><p>Updated 20261101</p></body></html>`

func capture(u, body string) Capture {
	return Capture{URL: u, StatusCode: 200, ContentType: "text/html", Body: body, FetchedAt: time.Now()}
}

func TestBuildAndCompare_Page(t *testing.T) {
	w := Watch{Mode: ModeFull}
	known := func(h string) bool { return h == "cdn.example.com" }
	s1 := Build(capture("https://shop.example.org/login", pageV1), w, known)
	if len(s1.Scripts) != 3 {
		t.Fatalf("scripts: %+v", s1.Scripts)
	}
	for _, sc := range s1.Scripts {
		if sc.ThirdParty {
			t.Errorf("first party marked third party: %+v", sc)
		}
	}
	for _, l := range s1.Text {
		if strings.Contains(l, "hidden") || strings.Contains(l, "body{") || strings.Contains(l, "csrf") {
			t.Errorf("non-visible text kept: %q", l)
		}
	}
	// Volatile tokens and a rebuilt bundle do not change the JS-only hash.
	js := Watch{Mode: ModeJS}
	a := Build(capture("https://shop.example.org/login", pageV1), js, known)
	b := Build(capture("https://shop.example.org/login", strings.ReplaceAll(strings.ReplaceAll(pageV1, "11aa22bb", "33cc44dd"), "r4nd0mN0nc3V4lu3xyz", "zzzzzzzzzzzzzzzzzzzzzz")), js, known)
	if a.ContentHash != b.ContentHash {
		t.Error("cache buster or nonce changed the hash")
	}
	s2 := Build(capture("https://shop.example.org/login", pageV2), w, known)
	d, sum, sev := Compare(s1, s2)
	if sev != SeverityHigh || len(d.NewThirdPartyHosts) != 1 || d.NewThirdPartyHosts[0] != "evil-skimmer.example.net" {
		t.Fatalf("sev %s diff %+v", sev, d)
	}
	if sum.ScriptsAdded != 1 || sum.ThirdPartyAdded != 1 || sum.LinesAdded != 1 || sum.LinesRemoved != 1 {
		t.Errorf("summary %+v (lines +%v -%v)", sum, d.LinesAdded, d.LinesRemoved)
	}
	// Ignore patterns drop a script before hashing.
	wi := Watch{Mode: ModeJS, IgnorePatterns: []string{`evil-skimmer`}}
	if Build(capture("https://shop.example.org/login", pageV2), wi, known).ContentHash != Build(capture("https://shop.example.org/login", pageV1), wi, known).ContentHash {
		t.Error("ignored script still changes the hash")
	}
	// A second script from a host already loaded is medium.
	s3 := Build(capture("https://shop.example.org/login", strings.Replace(pageV2, "</head>", `<script src="https://evil-skimmer.example.net/t.js"></script></head>`, 1)), w, known)
	if _, _, sev := Compare(s2, s3); sev != SeverityMedium {
		t.Errorf("same-host third-party script: %s", sev)
	}
	if got := DerivedScripts(s2); len(got) != 2 || !strings.Contains(got[0].Src, "/static/app.99ff88ee.js") {
		t.Errorf("derived: %+v", got)
	}
}

func TestBuildAndCompare_Script(t *testing.T) {
	w := Watch{Mode: ModeJS, IgnorePatterns: []string{`/health`}}
	c1 := Capture{URL: "https://a.example/app.js", StatusCode: 200, ContentType: "application/javascript",
		Body: `fetch("/api/v1/users");x="https://api.example.com/v2/x";y="/health";z="//cdn.x/y"`, SHA256: strings.Repeat("a", 64), Size: 10}
	s1 := Build(c1, w, nil)
	if s1.Kind != KindScript || len(s1.URLs) != 2 {
		t.Fatalf("urls %v", s1.URLs)
	}
	c2 := c1
	c2.Body += `;fetch("/api/internal/debug")`
	c2.SHA256, c2.Size = strings.Repeat("b", 64), 20
	s2 := Build(c2, w, nil)
	d, sum, sev := Compare(s1, s2)
	if sev != SeverityLow || !sum.ContentChanged || len(d.URLsAdded) != 1 || d.SizeFrom != 10 || d.SizeTo != 20 {
		t.Errorf("sev %s diff %+v", sev, d)
	}
}

func TestParseHTML_Bounded(t *testing.T) {
	body := strings.Repeat(`<script src="/a`, 1000) + strings.Repeat("<div>", 300000)
	u, _ := url.Parse("https://x.example/")
	scripts, _ := ParseHTML(body, u, true)
	if len(scripts) > MaxScripts {
		t.Errorf("scripts not capped: %d", len(scripts))
	}
	if got := ExtractURLs(strings.Repeat(`"/p`+"x\" ", 10) + strings.Repeat(`"/a`, 1)); len(got) > MaxURLsPerFile {
		t.Error("urls not capped")
	}
}

func TestFirstParty(t *testing.T) {
	if !FirstParty("www.example.co.uk", "static.example.co.uk", nil) {
		t.Error("same registrable domain")
	}
	if FirstParty("www.example.co.uk", "example2.co.uk", nil) {
		t.Error("different registrable domain")
	}
}
