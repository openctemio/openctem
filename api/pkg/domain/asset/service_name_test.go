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
		{"vndirect.com.vn:443:tcp", "vndirect.com.vn", 443, "tcp", true},
		{"VNDirect.com.vn.:443/tcp", "vndirect.com.vn", 443, "tcp", true},
		{"vndirect.com.vn:443", "vndirect.com.vn", 443, "tcp", true},
		{"203.0.113.5:53:udp", "203.0.113.5", 53, "udp", true},
		{"203.0.113.5:443/tcp", "203.0.113.5", 443, "tcp", true},
		{"[2001:db8::1]:443/tcp", "2001:db8::1", 443, "tcp", true},
		{"[2001:db8::1]:443:tcp", "2001:db8::1", 443, "tcp", true},
		{"[2001:db8::1]:443", "2001:db8::1", 443, "tcp", true},
		{"2001:db8::1:443:tcp", "2001:db8::1", 443, "tcp", true},
		{"2001:db8::1:443", "", 0, "", false},
		{"2001:db8::1", "", 0, "", false},
		{"vndirect.com.vn", "", 0, "", false},
		{"https://vndirect.com.vn:443", "", 0, "", false},
		{"vndirect.com.vn:443/admin", "", 0, "", false},
		{"vndirect.com.vn:70000:tcp", "", 0, "", false},
		{"vndirect.com.vn:0:tcp", "", 0, "", false},
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
		"vndirect.com.vn:443:tcp":         "vndirect.com.vn",
		"vndirect.com.vn:443/tcp":         "vndirect.com.vn",
		"https://Shop.Vndirect.com.vn/x":  "shop.vndirect.com.vn",
		"vndirect.com.vn:8443/admin":      "vndirect.com.vn",
		"vndirect.com.vn/path":            "vndirect.com.vn",
		"Vndirect.com.vn.":                "vndirect.com.vn",
		"[2001:db8::1]:443/tcp":           "2001:db8::1",
		"2001:db8::1:443:tcp":             "2001:db8::1",
		"2001:db8::1":                     "2001:db8::1",
		"202.160.124.20":                  "202.160.124.20",
		"202.160.124.20:443:tcp":          "202.160.124.20",
		"[2001:db8::1]":                   "2001:db8::1",
		"203.0.113.0/24":                  "203.0.113.0/24",
		"http://[2001:db8::1]:8080/index": "2001:db8::1",
	} {
		if got := HostOf(in); got != want {
			t.Errorf("HostOf(%q) = %q, want %q", in, got, want)
		}
	}
}
