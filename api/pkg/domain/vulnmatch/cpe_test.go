package vulnmatch

import (
	"strings"
	"testing"
)

func TestParseCPE(t *testing.T) {
	cases := []struct {
		in   string
		want CPE
		key  string
	}{
		{
			in:   "cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*",
			want: CPE{Part: "a", Vendor: "f5", Product: "nginx", Version: "1.18.0", Update: "*", SWEdition: "*", TargetSW: "*"},
			key:  "cpe:a:f5:nginx",
		},
		{
			in:   "CPE:2.3:A:Apache:HTTP_Server:2.4.41:*:*:*:*:*:*:*",
			want: CPE{Part: "a", Vendor: "apache", Product: "http_server", Version: "2.4.41", Update: "*", SWEdition: "*", TargetSW: "*"},
			key:  "cpe:a:apache:http_server",
		},
		{
			in:   "cpe:2.3:a:openbsd:openssh:8.2:p1:*:*:*:*:*:*",
			want: CPE{Part: "a", Vendor: "openbsd", Product: "openssh", Version: "8.2", Update: "p1", SWEdition: "*", TargetSW: "*"},
			key:  "cpe:a:openbsd:openssh",
		},
		{
			in:   "cpe:2.3:o:microsoft:windows_10:-:*:*:*:*:*:*:*",
			want: CPE{Part: "o", Vendor: "microsoft", Product: "windows_10", Version: "-", Update: "*", SWEdition: "*", TargetSW: "*"},
			key:  "cpe:o:microsoft:windows_10",
		},
		{
			in:   `cpe:2.3:a:joomla:joomla\!:3.9.0:*:*:*:*:*:*:*`,
			want: CPE{Part: "a", Vendor: "joomla", Product: "joomla!", Version: "3.9.0", Update: "*", SWEdition: "*", TargetSW: "*"},
			key:  "cpe:a:joomla:joomla!",
		},
		{
			in:   `cpe:2.3:a:vendor:prod\:uct:1.0:*:*:*:*:node.js:*:*`,
			want: CPE{Part: "a", Vendor: "vendor", Product: "prod:uct", Version: "1.0", Update: "*", SWEdition: "*", TargetSW: "node.js"},
			key:  "cpe:a:vendor:prod:uct",
		},
		{
			in:   "cpe:2.3:a:nginx:nginx", // short form
			want: CPE{Part: "a", Vendor: "nginx", Product: "nginx", Version: "*", Update: "*", SWEdition: "*", TargetSW: "*"},
			key:  "cpe:a:nginx:nginx",
		},
		{
			in:   "cpe:/a:nginx:nginx:1.18.0",
			want: CPE{Part: "a", Vendor: "nginx", Product: "nginx", Version: "1.18.0", Update: "*", SWEdition: "*", TargetSW: "*"},
			key:  "cpe:a:nginx:nginx",
		},
		{
			in:   "cpe:/a:igor_sysoev:nginx:0.7%2e65",
			want: CPE{Part: "a", Vendor: "igor_sysoev", Product: "nginx", Version: "0.7.65", Update: "*", SWEdition: "*", TargetSW: "*"},
			key:  "cpe:a:igor_sysoev:nginx",
		},
	}
	cases = append(cases, struct {
		in   string
		want CPE
		key  string
	}{
		in:   "cpe:2.3:a:gitlab:gitlab:*:*:*:*:community:*:*:*",
		want: CPE{Part: "a", Vendor: "gitlab", Product: "gitlab", Version: "*", Update: "*", SWEdition: "community", TargetSW: "*"},
		key:  "cpe:a:gitlab:gitlab",
	})
	for _, c := range cases {
		got, err := ParseCPE(c.in)
		if err != nil {
			t.Errorf("ParseCPE(%q): %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("ParseCPE(%q) = %+v, want %+v", c.in, got, c.want)
		}
		if got.Key() != c.key {
			t.Errorf("Key(%q) = %q, want %q", c.in, got.Key(), c.key)
		}
	}
}

func TestParseCPE_Refuses(t *testing.T) {
	for _, s := range []string{
		"",
		"nginx",
		"cpe:2.3",
		"cpe:2.3:a",
		"cpe:2.3:a:nginx", // no product
		"cpe:2.3:x:nginx:nginx:1.0:*:*:*:*:*:*:*",     // bad part
		"cpe:2.3:a:*:nginx:1.0:*:*:*:*:*:*:*",         // any vendor
		"cpe:2.3:a:nginx:*:1.0:*:*:*:*:*:*:*",         // any product
		"cpe:2.3:a:-:nginx:1.0:*:*:*:*:*:*:*",         // NA vendor
		"cpe:2.3:a:ngi*:nginx:1.0:*:*:*:*:*:*:*",      // wildcard in vendor
		"cpe:2.3:a:nginx:ng?nx:1.0:*:*:*:*:*:*:*",     // wildcard in product
		"cpe:2.3:a::nginx:1.0:*:*:*:*:*:*:*",          // empty vendor
		"cpe:2.3:a:nginx:nginx:1.0:*:*:*:*:*:*:*:*:*", // too many fields
		"cpe:2.3:a:ngi\x01nx:nginx:1.0",
		"cpe:2.3:a:" + strings.Repeat("v", 129) + ":p:1",
		"cpe:2.3:a:v:p:" + strings.Repeat("1", MaxCPELen),
	} {
		if c, err := ParseCPE(s); err == nil {
			t.Errorf("ParseCPE(%q) accepted: %+v", s, c)
		}
	}
}

func TestValidMatchKey(t *testing.T) {
	for k, want := range map[string]bool{
		"cpe:a:f5:nginx":          true,
		"cpe:o:microsoft:windows": true,
		"cpe:a:joomla:joomla!":    true,
		"cpe:a:f5":                false,
		"cpe:x:f5:nginx":          false,
		"cpe:a:*:nginx":           false,
		"cpe:a:f5:*":              false,
		"cpe:a:F5:nginx":          false,
		"cpe:a:f5:ng:inx":         false,
		"name:nginx":              false,
		"cpe:a:f5:ngi\nx":         false,
		"cpe:a:" + strings.Repeat("v", 600) + ":p": false,
	} {
		if got := ValidMatchKey(k); got != want {
			t.Errorf("ValidMatchKey(%q) = %v, want %v", k, got, want)
		}
	}
}

func FuzzParseCPE(f *testing.F) {
	for _, s := range []string{
		"cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*",
		`cpe:2.3:a:joomla:joomla\!:3.9.0:*:*:*:*:*:*:*`,
		"cpe:/a:nginx:nginx:1.18.0",
		"cpe:2.3:a:*:*",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		c, err := ParseCPE(s)
		if err != nil {
			return
		}
		if !ValidMatchKey(c.Key()) && !strings.Contains(c.Product, ":") {
			t.Fatalf("parsed %q to an invalid key %q", s, c.Key())
		}
		if c.Vendor == Any || c.Product == Any {
			t.Fatalf("parsed %q to a wildcard identity", s)
		}
	})
}
