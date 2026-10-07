package retest

import "testing"

func TestResolveTarget(t *testing.T) {
	cases := []struct {
		name, matchedAt, asset, want string
	}{
		// The origin of the matched-at URL, never the URL itself: the template
		// appends its own path to the input, so a matched-at input requests the
		// path twice and always misses (a false "fixed").
		{"matched-at on the asset's host becomes its origin", "https://shop.example.com/admin/login.php", "shop.example.com", "https://shop.example.com"},
		{"a template path is not repeated", "https://shop.example.com/wp-admin/js/theme.js", "shop.example.com", "https://shop.example.com"},
		{"query and fragment are dropped", "https://shop.example.com/x?token=abc#f", "shop.example.com", "https://shop.example.com"},
		{"host match is case-insensitive", "https://SHOP.example.com/x", "shop.example.com", "https://shop.example.com"},
		{"scheme is lower-cased", "HTTPS://shop.example.com/x", "shop.example.com", "https://shop.example.com"},
		{"explicit port is kept", "http://api.example.com:8080/v1", "https://api.example.com", "http://api.example.com:8080"},
		{"asset given as host:port", "https://api.example.com/v1", "api.example.com:443", "https://api.example.com"},
		{"userinfo is dropped", "https://user:pw@shop.example.com/x", "shop.example.com", "https://shop.example.com"},
		// A finding cannot point a retest at a host that is not its asset.
		{"matched-at on another host falls back to the asset", "https://evil.example.net/", "shop.example.com", "shop.example.com"},
		{"a subdomain of the asset is another host", "https://a.shop.example.com/", "shop.example.com", "shop.example.com"},
		{"non-http scheme falls back", "file://shop.example.com/etc/passwd", "shop.example.com", "shop.example.com"},
		{"no matched-at uses the asset", "", "10.0.0.5", "10.0.0.5"},
		{"a network matched-at (host:port) uses the asset", "shop.example.com:22", "shop.example.com", "shop.example.com"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := ResolveTarget(c.matchedAt, c.asset); got != c.want {
				t.Errorf("ResolveTarget(%q, %q) = %q, want %q", c.matchedAt, c.asset, got, c.want)
			}
		})
	}
}
