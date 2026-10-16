package config

import "testing"

// The version check reads its feed over https only, from a URL without
// credentials, query or fragment; unset means the built-in default.
func TestVersionCheckURL(t *testing.T) {
	for name, tc := range map[string]struct {
		url string
		ok  bool
	}{
		"unset":       {ok: true},
		"https":       {url: "https://mirror.example/openctem-releases.json", ok: true},
		"http":        {url: "http://mirror.example/openctem-releases.json"},
		"credentials": {url: "https://u:p@mirror.example/f.json"},
		"query":       {url: "https://mirror.example/f.json?x=1"},
		"fragment":    {url: "https://mirror.example/f.json#x"},
		"file":        {url: "file:///etc/passwd"},
	} {
		t.Run(name, func(t *testing.T) {
			c := minimalValidConfig()
			c.Worker.VersionCheckURL = tc.url
			if err := c.validateBasic(); (err == nil) != tc.ok {
				t.Fatalf("validateBasic = %v, want ok=%v", err, tc.ok)
			}
		})
	}
}
