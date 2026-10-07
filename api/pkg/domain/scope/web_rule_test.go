package scope

import (
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestNormalizePathPrefix(t *testing.T) {
	ok := map[string]string{
		"/admin/debug":   "/admin/debug",
		"/admin/debug/":  "/admin/debug",
		"/admin/debug/*": "/admin/debug",
		"//api//v1/":     "/api/v1",
		"/api/*/admin":   "/api/*/admin",
		"/":              "/",
		"/*":             "/",
	}
	for in, want := range ok {
		got, err := NormalizePathPrefix(in)
		if err != nil || got != want {
			t.Errorf("NormalizePathPrefix(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "admin", "/a?b=1", "/a#x", "/a/../b", "/a/./b", "/adm*n", "/a%2fb", "/a%5Cb", "/a\\b", "/a\x00b", "/a\nb"} {
		if _, err := NormalizePathPrefix(bad); !errors.Is(err, ErrInvalidPattern) {
			t.Errorf("NormalizePathPrefix(%q) err = %v, want ErrInvalidPattern", bad, err)
		}
	}
}

func TestPathUnder_SegmentAware(t *testing.T) {
	cases := []struct {
		path, prefix string
		want         bool
	}{
		{"/admin/debug", "/admin/debug", true},
		{"/admin/debug/x/y", "/admin/debug", true},
		{"/admin/debugger", "/admin/debug", false},
		{"/admin", "/admin/debug", false},
		{"/api/v2/admin/users", "/api/*/admin", true},
		{"/api/v2/public", "/api/*/admin", false},
		{"/anything", "/", true},
		{"/Admin/debug", "/admin/debug", false}, // paths are case-sensitive
	}
	for _, c := range cases {
		if got := PathUnder(c.path, c.prefix); got != c.want {
			t.Errorf("PathUnder(%q, %q) = %v, want %v", c.path, c.prefix, got, c.want)
		}
	}
}

func TestHostPatternMatches(t *testing.T) {
	cases := []struct {
		pattern, host string
		want          bool
	}{
		{"*", "anything.example", true},
		{"*.example.com", "example.com", true}, // RFC-054 S1: the apex too
		{"*.example.com", "a.b.example.com", true},
		{"*.example.com", "badexample.com", false},
		{"api.example.com", "API.example.com.", true},
		{"api.example.com", "x.api.example.com", false},
		{"https://api.example.com:8443", "api.example.com", true},
		{"10.0.0.1", "10.0.0.1", true},
	}
	for _, c := range cases {
		if got := HostPatternMatches(c.pattern, c.host); got != c.want {
			t.Errorf("HostPatternMatches(%q, %q) = %v, want %v", c.pattern, c.host, got, c.want)
		}
	}
	for _, bad := range []string{"https://x.example/path", "a*.example.com", "*.*.example.com", "x.example/admin", "user@x.example"} {
		if ValidateHostPattern(bad) == nil {
			t.Errorf("ValidateHostPattern(%q) accepted", bad)
		}
	}
}

func TestWebRule_MethodsAndTestingModes(t *testing.T) {
	now := time.Now()
	all := &WebRule{PathPrefix: "/admin", Testing: TestingBlocked}
	if !all.Blocks("GET", "/admin/x", now) || !all.Blocks("DELETE", "/admin", now) || all.Blocks("GET", "/public", now) {
		t.Fatal("an all-methods rule must block every method under its prefix only")
	}
	if !all.Blocks("ANY", "/admin", now) {
		t.Fatal("an endpoint of unknown method is checked as GET")
	}

	writes := &WebRule{PathPrefix: "/admin", Methods: []string{"POST", "PUT", "DELETE"}, Testing: TestingBlocked}
	if writes.Blocks("GET", "/admin", now) || !writes.Blocks("POST", "/admin", now) {
		t.Fatal("a method-scoped rule must block only its methods")
	}

	ro := &WebRule{PathPrefix: "/admin", Testing: TestingReadOnly}
	if ro.Blocks("GET", "/admin", now) || ro.Blocks("HEAD", "/admin", now) || !ro.Blocks("POST", "/admin", now) || !ro.Blocks("OPTIONS", "/admin", now) {
		t.Fatal("read_only lets GET and HEAD through and nothing else")
	}

	until := now.Add(time.Hour)
	allowed := &WebRule{PathPrefix: "/admin", Testing: TestingAllowed, TestingUntil: &until}
	if allowed.Blocks("DELETE", "/admin", now) {
		t.Fatal("allowed blocks nothing inside its window")
	}
	if !allowed.Blocks("GET", "/admin", now.Add(2*time.Hour)) || allowed.EffectiveTesting(now.Add(2*time.Hour)) != TestingBlocked {
		t.Fatal("allowed must revert to blocked at testing_until")
	}
	var nilRule *WebRule
	if nilRule.Blocks("GET", "/admin", now) || nilRule.EffectiveTesting(now) != TestingBlocked {
		t.Fatal("nil rule")
	}
}

func TestPathExclusion_NeverExcludesAWholeAsset(t *testing.T) {
	e, err := NewExclusion(shared.NewID(), ExclusionTypePath, "*.example.com", "debug console", nil, "u")
	if err != nil {
		t.Fatal(err)
	}
	e.SetWeb(&WebRule{PathPrefix: "/admin/debug", Testing: TestingBlocked})
	for v, want := range map[string]bool{
		"app.example.com":                        false, // a host: never excluded by a path rule
		"https://app.example.com":                false,
		"https://app.example.com/admin/debug":    true,
		"https://app.example.com/admin/debug/x":  true,
		"https://app.example.com/admin/debugger": false,
		"https://other.test/admin/debug":         false,
		"https://example.com/admin/%64ebug":      true, // decoded before matching
	} {
		if got := e.Matches(v); got != want {
			t.Errorf("Matches(%q) = %v, want %v", v, got, want)
		}
	}
	if MatchesExclusionPattern(ExclusionTypePath, "*", "https://x/admin") {
		t.Fatal("the pattern alone must never apply a path rule")
	}
}

func TestNormalizeMethods(t *testing.T) {
	got, err := NormalizeMethods([]string{"post", "PUT", "post"})
	if err != nil || !slices.Equal(got, []string{"POST", "PUT"}) {
		t.Fatalf("got %v %v", got, err)
	}
	if got, _ := NormalizeMethods([]string{"*"}); len(got) != 0 {
		t.Fatal("* means every method (empty)")
	}
	if _, err := NormalizeMethods([]string{"BREW"}); err == nil {
		t.Fatal("unknown method accepted")
	}
}
