package retest

import "testing"

func TestResolveTarget(t *testing.T) {
	cases := []struct {
		name, matchedAt, asset, want string
	}{
		{"matched-at on the asset's host is kept", "https://shop.example.com/admin/login.php", "shop.example.com", "https://shop.example.com/admin/login.php"},
		{"host match is case-insensitive", "https://SHOP.example.com/x", "shop.example.com", "https://SHOP.example.com/x"},
		{"asset given as URL", "http://api.example.com:8080/v1", "https://api.example.com", "http://api.example.com:8080/v1"},
		{"asset given as host:port", "https://api.example.com/v1", "api.example.com:443", "https://api.example.com/v1"},
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
