package config

import (
	"slices"
	"testing"
)

// Program feed origins are operator configuration: https only, no
// credentials, query or fragment (the fetcher appends file names).
func TestProgramFeedURLs(t *testing.T) {
	got := feedURLs(" https://releases.example/feed/ ", "https://m1.example/f, ,https://m2.example/f/")
	want := []string{"https://releases.example/feed", "https://m1.example/f", "https://m2.example/f"}
	if !slices.Equal(got, want) {
		t.Fatalf("feedURLs = %v, want %v", got, want)
	}
	if feedURLs("", "") != nil {
		t.Fatal("empty configuration gave origins")
	}
	for name, tc := range map[string]struct {
		urls []string
		ok   bool
	}{
		"none":        {ok: true},
		"https":       {urls: []string{"https://releases.example/feed"}, ok: true},
		"http":        {urls: []string{"http://releases.example/feed"}},
		"credentials": {urls: []string{"https://u:p@releases.example/feed"}},
		"query":       {urls: []string{"https://releases.example/feed?token=x"}},
		"fragment":    {urls: []string{"https://releases.example/feed#x"}},
		"file":        {urls: []string{"file:///etc"}},
	} {
		t.Run(name, func(t *testing.T) {
			c := minimalValidConfig()
			c.Scope.ProgramFeedURLs = tc.urls
			if err := c.validateBasic(); (err == nil) != tc.ok {
				t.Fatalf("validateBasic = %v, want ok=%v", err, tc.ok)
			}
		})
	}
}
