package assettech

import (
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestClassify(t *testing.T) {
	cases := []struct {
		name string
		cats []string
		want Category
	}{
		{"HSTS", nil, CategorySecurityHeader},
		{"Vercel", nil, CategoryHosting},
		{"Cloudflare", nil, CategoryCDN},
		{"nginx", nil, CategoryWebServer},
		{"Microsoft-IIS", nil, CategoryWebServer},
		{"Next.js", nil, CategoryFramework},
		{"PHP", nil, CategoryLanguage},
		{"jQuery", nil, CategoryJSLibrary},
		{"Google Analytics", nil, CategoryAnalytics},
		{"reCAPTCHA", nil, CategoryWAF},
		// The curated list wins over a tool's category.
		{"HSTS", []string{"Security"}, CategorySecurityHeader},
		// Unknown names fall back to the tool's categories, either spelling.
		{"Acme Server", []string{"Web servers"}, CategoryWebServer},
		{"Acme Server", []string{"web-server"}, CategoryWebServer},
		{"Acme Pages", []string{"PaaS"}, CategoryHosting},
		{"Acme Tag", []string{"unknown", "Tag managers"}, CategoryAnalytics},
		{"Acme", nil, CategoryOther},
	}
	for _, c := range cases {
		if got := Classify(Key(c.name), c.cats); got != c.want {
			t.Errorf("Classify(%q, %v) = %s, want %s", c.name, c.cats, got, c.want)
		}
	}
}

func TestCuratedNamesAreValidKeys(t *testing.T) {
	for k, c := range curatedNames {
		if k == "" || !c.IsValid() {
			t.Fatalf("bad curated entry %q -> %q", k, c)
		}
	}
}

func TestIsSoftwareCandidate(t *testing.T) {
	cases := []struct {
		name, version, cpe string
		cats               []string
		want               bool
	}{
		{"HSTS", "", "", nil, false},
		{"Vercel", "", "", nil, false},
		{"nginx", "", "", nil, false},             // no version, no CPE: nothing to match
		{"nginx", "1.18.0", "", nil, true},        // product + version
		{"Next.js", "13.4.1", "", nil, true},      // framework + version
		{"Cloudflare", "2", "", nil, false},       // CDN never, whatever the version
		{"Google Analytics", "4", "", nil, false}, // marketing never
		{"HSTS", "1", "", nil, false},             // header never
		{"", "", "cpe:2.3:a:f5:nginx:1.2:*:*:*:*:*:*:*", nil, true},
		{"Vercel", "", "cpe:2.3:a:vercel:vercel:-:*:*:*:*:*:*:*", nil, false},
		{"nginx", "1.\x00", "", nil, false}, // control character drops the version
		{strings.Repeat("a", MaxNameLen+1), "1.0", "", nil, false},
	}
	for _, c := range cases {
		if got := IsSoftwareCandidate(c.name, c.version, c.cpe, c.cats); got != c.want {
			t.Errorf("IsSoftwareCandidate(%q, %q, %q) = %v, want %v", c.name, c.version, c.cpe, got, c.want)
		}
	}
}

func TestObservationSanitizes(t *testing.T) {
	id := shared.NewID()
	now := time.Now()
	if _, ok := Observation(id, "  ", "", nil, 0, "", now); ok {
		t.Fatal("blank name accepted")
	}
	if _, ok := Observation(id, "evil\x1b[31m", "", nil, 0, "", now); ok {
		t.Fatal("control character accepted")
	}
	if _, ok := Observation(id, "bad\xff", "", nil, 0, "", now); ok {
		t.Fatal("invalid UTF-8 accepted")
	}
	if _, ok := Observation(id, strings.Repeat("x", MaxNameLen+1), "", nil, 0, "", now); ok {
		t.Fatal("over-long name accepted")
	}
	tech, ok := Observation(id, "  Next.js  ", strings.Repeat("9", MaxVersionLen+1), nil, 250, strings.Repeat("s", 300)+"\n", now)
	if !ok {
		t.Fatal("valid name rejected")
	}
	if tech.Name != "Next.js" || tech.Key != "next.js" || tech.Version != "" || tech.Confidence != 100 ||
		len(tech.Source) != MaxSourceLen || tech.Category != CategoryFramework {
		t.Fatalf("unexpected %+v", tech)
	}
	if tech, _ := Observation(id, "nginx", "1.25.3", nil, -5, "httpx", now); tech.Confidence != 0 || tech.Version != "1.25.3" {
		t.Fatalf("unexpected %+v", tech)
	}
}

func TestSplitAndElementKey(t *testing.T) {
	cases := map[string][2]string{
		"Next.js:13.4": {"Next.js", "13.4"},
		"Cloudflare":   {"Cloudflare", ""},
		"Name:Plugin":  {"Name:Plugin", ""},
		"PHP:v8.1":     {"PHP", "v8.1"},
	}
	for in, want := range cases {
		n, v := Split(in)
		if n != want[0] || v != want[1] {
			t.Errorf("Split(%q) = %q, %q", in, n, v)
		}
	}
	if ElementKey(" Next.js:13.4 ") != "next.js" {
		t.Fatal("element key")
	}
}

func TestParseFilters(t *testing.T) {
	got := ParseFilterValues("nginx, NGINX ,,Next.js,bad\x00")
	if len(got) != 2 || got[0] != "nginx" || got[1] != "next.js" {
		t.Fatalf("got %v", got)
	}
	many := strings.Repeat("a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,r,s,t,u,v,w,", 2)
	if n := len(ParseFilterValues(many)); n != MaxFilterValues {
		t.Fatalf("cap: %d", n)
	}
	cats := ParseCategories("cdn, Hosting,bogus,cdn")
	if len(cats) != 2 || cats[0] != CategoryCDN || cats[1] != CategoryHosting {
		t.Fatalf("got %v", cats)
	}
}

func TestKinds(t *testing.T) {
	want := map[Category]Kind{
		CategoryCDN: KindInfrastructure, CategoryHosting: KindInfrastructure, CategoryWAF: KindInfrastructure,
		CategorySecurityHeader: KindHTTPSecurity, CategoryAnalytics: KindMarketing,
		CategoryWebServer: KindSoftware, CategoryOther: KindSoftware,
	}
	for c, k := range want {
		if c.Kind() != k {
			t.Errorf("%s kind %s", c, c.Kind())
		}
	}
}

func TestCollapse(t *testing.T) {
	got := Collapse([]string{"nginx:1.9", "nginx:1.18.0", "NGINX", "  Next.js  ", "Next.js:13.4", "bad\x00", "HSTS", "hsts"})
	want := []string{"HSTS", "Next.js:13.4", "nginx:1.18.0"}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
	// Stable: collapsing the result changes nothing.
	again := Collapse(got)
	for i := range got {
		if again[i] != got[i] {
			t.Fatalf("not stable: %v vs %v", again, got)
		}
	}
	if Element("  Next.js ", " 13.4 ") != "Next.js:13.4" || Element("x\x00", "1") != "" || Element("PHP", "") != "PHP" {
		t.Fatal("element form")
	}
}
