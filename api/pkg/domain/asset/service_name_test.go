package asset

import "testing"

func TestSplitServiceName(t *testing.T) {
	for _, c := range []struct {
		in    string
		host  string
		port  int
		proto string
		ok    bool
	}{
		{"example.co.uk:443:tcp", "example.co.uk", 443, "tcp", true},
		{"EXAMPLE.co.uk.:443/tcp", "example.co.uk", 443, "tcp", true},
		{"example.co.uk:443", "example.co.uk", 443, "tcp", true},
		{"203.0.113.5:53:udp", "203.0.113.5", 53, "udp", true},
		{"203.0.113.5:443/tcp", "203.0.113.5", 443, "tcp", true},
		{"[2001:db8::1]:443/tcp", "2001:db8::1", 443, "tcp", true},
		{"[2001:db8::1]:443:tcp", "2001:db8::1", 443, "tcp", true},
		{"[2001:db8::1]:443", "2001:db8::1", 443, "tcp", true},
		{"2001:db8::1:443:tcp", "2001:db8::1", 443, "tcp", true},
		{"2001:db8::1:443", "", 0, "", false},
		{"2001:db8::1", "", 0, "", false},
		{"example.co.uk", "", 0, "", false},
		{"https://example.co.uk:443", "", 0, "", false},
		{"example.co.uk:443/admin", "", 0, "", false},
		{"example.co.uk:70000:tcp", "", 0, "", false},
		{"example.co.uk:0:tcp", "", 0, "", false},
		{"[not-an-ip]:443/tcp", "", 0, "", false},
		{"", "", 0, "", false},
	} {
		h, p, pr, ok := SplitServiceName(c.in)
		if h != c.host || p != c.port || pr != c.proto || ok != c.ok {
			t.Errorf("SplitServiceName(%q) = %q %d %q %v, want %q %d %q %v", c.in, h, p, pr, ok, c.host, c.port, c.proto, c.ok)
		}
	}
}

func TestHostOf(t *testing.T) {
	for in, want := range map[string]string{
		"example.co.uk:443:tcp":           "example.co.uk",
		"example.co.uk:443/tcp":           "example.co.uk",
		"https://Shop.Example.co.uk/x":    "shop.example.co.uk",
		"example.co.uk:8443/admin":        "example.co.uk",
		"example.co.uk/path":              "example.co.uk",
		"Example.co.uk.":                  "example.co.uk",
		"[2001:db8::1]:443/tcp":           "2001:db8::1",
		"2001:db8::1:443:tcp":             "2001:db8::1",
		"2001:db8::1":                     "2001:db8::1",
		"198.51.100.20":                   "198.51.100.20",
		"198.51.100.20:443:tcp":           "198.51.100.20",
		"[2001:db8::1]":                   "2001:db8::1",
		"203.0.113.0/24":                  "203.0.113.0/24",
		"http://[2001:db8::1]:8080/index": "2001:db8::1",
	} {
		if got := HostOf(in); got != want {
			t.Errorf("HostOf(%q) = %q, want %q", in, got, want)
		}
	}
}
