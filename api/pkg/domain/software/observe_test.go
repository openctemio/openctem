package software

import (
	"reflect"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/vulnmatch"
)

func TestCuratedProductsAreConsistent(t *testing.T) {
	names := map[string]string{}
	cpes := map[string]string{}
	for _, p := range CuratedProducts() {
		key := vulnmatch.MatchKey(p.Part, p.CPEVendor, p.CPEProduct)
		if !vulnmatch.ValidMatchKey(key) {
			t.Errorf("%s: invalid CPE key %q", p.Name, key)
		}
		all := append([]string{p.CPEVendor + ":" + p.CPEProduct}, p.AltCPE...)
		for _, c := range all {
			k := p.Part + ":" + c
			if prev, dup := cpes[k]; dup {
				t.Errorf("CPE %s on %s and %s", k, prev, p.Name)
			}
			cpes[k] = p.Name
			if !vulnmatch.ValidMatchKey("cpe:" + k) {
				t.Errorf("%s: invalid alt CPE %q", p.Name, c)
			}
		}
		if len(p.Names) == 0 {
			t.Errorf("%s: no names", p.Name)
		}
		for _, n := range p.Names {
			if n != NormalizeName(n) {
				t.Errorf("%s: name %q is not normalised", p.Name, n)
			}
			if genericServiceNames[n] {
				t.Errorf("%s: name %q is a generic service name", p.Name, n)
			}
			if prev, dup := names[n]; dup {
				t.Errorf("name %q on %s and %s", n, prev, p.Name)
			}
			names[n] = p.Name
		}
	}
	if len(CuratedProducts()) < 60 {
		t.Fatalf("only %d curated products", len(CuratedProducts()))
	}
}

func TestSplitVersion(t *testing.T) {
	cases := []struct{ in, ver, qual string }{
		{"", "", ""},
		{"1.18.0", "1.18.0", ""},
		{"8.2p1 Ubuntu-4ubuntu0.5", "8.2p1", "ubuntu-4ubuntu0.5"},
		{"8.2p1 Ubuntu 4ubuntu0.5", "8.2p1", "ubuntu-4ubuntu0.5"},
		{"2.4.41 (Ubuntu)", "2.4.41", "ubuntu"},
		{"2.4.6 (CentOS)", "2.4.6", "centos"},
		{"2.4.6 (Red Hat Enterprise Linux)", "2.4.6", "red-hat-enterprise-linux"},
		{"1.18.0-0ubuntu1.4", "1.18.0", "0ubuntu1.4"},
		{"2.4.6-el7_9", "2.4.6", "el7_9"},
		{"9.2p1-2+deb12u2", "9.2p1", "2+deb12u2"},
		{"1.0.2k-fips", "1.0.2k", "fips"},
		{"2.4.58 (Win64)", "2.4.58", ""},
		{"2.4.58-rc1", "2.4.58-rc1", ""},
		{"1.2.3-beta.1", "1.2.3-beta.1", ""},
		{"7.4.3-1+deb11u1 (Debian)", "7.4.3-1+deb11u1", "debian"},
		{strings.Repeat("1", 80), strings.Repeat("1", 64), ""},
	}
	for _, c := range cases {
		v, q := SplitVersion(c.in)
		if v != c.ver || q != c.qual {
			t.Errorf("SplitVersion(%q) = %q, %q; want %q, %q", c.in, v, q, c.ver, c.qual)
		}
	}
}

func TestParseBanner(t *testing.T) {
	cases := []struct {
		in   string
		want []Banner
	}{
		{"nginx/1.18.0 (Ubuntu)", []Banner{{"nginx", "1.18.0 (Ubuntu)"}}},
		{"nginx", nil},
		{"Microsoft-IIS/10.0", []Banner{{"Microsoft-IIS", "10.0"}}},
		{"Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips PHP/5.4.16", []Banner{
			{"Apache", "2.4.6 (CentOS)"}, {"OpenSSL", "1.0.2k-fips"}, {"PHP", "5.4.16"},
		}},
		{"OpenSSH_8.2p1 Ubuntu-4ubuntu0.5", []Banner{{"OpenSSH", "8.2p1 Ubuntu-4ubuntu0.5"}}},
		{"OpenSSH 8.2p1 Ubuntu 4ubuntu0.5", []Banner{{"OpenSSH", "8.2p1 Ubuntu 4ubuntu0.5"}}},
		{"Apache httpd 2.4.41", []Banner{{"Apache httpd", "2.4.41"}}},
		{"cloudflare", nil},
		{"", nil},
		{"bad\x00banner/1.0", nil},
	}
	for _, c := range cases {
		got := ParseBanner(c.in)
		if !reflect.DeepEqual(got, c.want) && !(len(got) == 0 && len(c.want) == 0) {
			t.Errorf("ParseBanner(%q) = %+v, want %+v", c.in, got, c.want)
		}
	}
	if got := ParseBanner(strings.Repeat("a/1 ", 50)); len(got) != 8 {
		t.Errorf("banner cap: %d", len(got))
	}
}

func TestSplitTechnology(t *testing.T) {
	for in, want := range map[string][2]string{
		"Nginx:1.18.0":      {"Nginx", "1.18.0"},
		"PHP:7.4.3":         {"PHP", "7.4.3"},
		"Cloudflare":        {"Cloudflare", ""},
		"HTTP/3":            {"HTTP/3", ""},
		"Font Awesome:5.15": {"Font Awesome", "5.15"},
		"Some:Thing":        {"Some:Thing", ""},
	} {
		n, v := SplitTechnology(in)
		if n != want[0] || v != want[1] {
			t.Errorf("SplitTechnology(%q) = %q, %q", in, n, v)
		}
	}
}

func TestParse(t *testing.T) {
	cases := []struct {
		name string
		o    Observation
		ok   bool
		id   Identity
		ver  VersionKey
		segs int
	}{
		{"name and version", Observation{Name: " Nginx ", Version: "1.18.0"}, true,
			Identity{Part: "a", Name: "nginx"}, VersionKey{Raw: "1.18.0", Normalized: "1.18", Scheme: vulnmatch.SchemeGeneric}, 3},
		{"distro build", Observation{Name: "OpenSSH", Version: "8.2p1 Ubuntu-4ubuntu0.5"}, true,
			Identity{Part: "a", Name: "openssh"}, VersionKey{Raw: "8.2p1", Normalized: "8.2.p.1", Scheme: vulnmatch.SchemeGeneric, Qualifier: "ubuntu-4ubuntu0.5"}, 4},
		{"cpe with version", Observation{CPE: "cpe:2.3:a:openbsd:openssh:8.2:p1:*:*:*:*:*:*"}, true,
			Identity{Part: "a", CPEVendor: "openbsd", CPEProduct: "openssh"}, VersionKey{Raw: "8.2p1", Normalized: "8.2.p.1", Scheme: vulnmatch.SchemeGeneric}, 4},
		{"cpe edition", Observation{CPE: "cpe:2.3:a:gitlab:gitlab:16.1.0:*:*:*:enterprise:*:*:*"}, true,
			Identity{Part: "a", CPEVendor: "gitlab", CPEProduct: "gitlab", Edition: "enterprise"},
			VersionKey{Raw: "16.1.0", Normalized: "16.1", Scheme: vulnmatch.SchemeGeneric, Edition: "enterprise"}, 3},
		{"version beats cpe version", Observation{CPE: "cpe:2.3:a:f5:nginx:1.0:*:*:*:*:*:*:*", Version: "1.2"}, true,
			Identity{Part: "a", CPEVendor: "f5", CPEProduct: "nginx"}, VersionKey{Raw: "1.2", Normalized: "1.2", Scheme: vulnmatch.SchemeGeneric}, 2},
		{"bad cpe falls back to name", Observation{CPE: "cpe:2.3:a:*:*", Name: "nginx"}, true,
			Identity{Part: "a", Name: "nginx"}, VersionKey{Scheme: vulnmatch.SchemeGeneric}, 0},
		{"unparseable version kept raw", Observation{Name: "nginx", Version: "latest"}, true,
			Identity{Part: "a", Name: "nginx"}, VersionKey{Raw: "latest", Scheme: vulnmatch.SchemeGeneric}, 0},
		{"os", Observation{Name: "Ubuntu", Version: "22.04", Source: SourceOS}, true,
			Identity{Part: "o", Name: "ubuntu"}, VersionKey{Raw: "22.04", Normalized: "22.4", Scheme: vulnmatch.SchemeGeneric}, 2},
		{"generic service name", Observation{Name: "ssh", Version: "8.2"}, false, Identity{}, VersionKey{}, 0},
		{"nothing", Observation{Version: "1.0"}, false, Identity{}, VersionKey{}, 0},
		{"control char", Observation{Name: "ngi\x01nx"}, false, Identity{}, VersionKey{}, 0},
		{"too long", Observation{Name: strings.Repeat("n", 201)}, false, Identity{}, VersionKey{}, 0},
	}
	for _, c := range cases {
		p, ok := Parse(c.o)
		if ok != c.ok {
			t.Errorf("%s: ok=%v", c.name, ok)
			continue
		}
		if !ok {
			continue
		}
		if p.Identity != c.id || p.Version != c.ver || p.Segments != c.segs {
			t.Errorf("%s: got %+v", c.name, p)
		}
	}
}

func TestConfidence(t *testing.T) {
	parse := func(o Observation) Parsed {
		p, ok := Parse(o)
		if !ok {
			t.Fatalf("parse %+v", o)
		}
		return p
	}
	cases := []struct {
		name   string
		o      Observation
		global bool
		want   int
	}{
		{"cpe resolved", Observation{CPE: "cpe:2.3:a:f5:nginx:1.18.0"}, true, 80},
		{"curated name", Observation{Name: "nginx", Version: "1.18.0"}, true, 65},
		{"private name", Observation{Name: "acme-portal", Version: "1.2.3"}, false, 50},
		{"partial version", Observation{Name: "nginx", Version: "1.18"}, true, 40},
		{"distro build", Observation{Name: "openssh", Version: "8.2p1 Ubuntu-4ubuntu0.5"}, true, 35},
		{"low tool confidence", Observation{Name: "nginx", Version: "1.18.0", ToolConfidence: 30}, true, 50},
		{"high tool confidence", Observation{Name: "nginx", Version: "1.18.0", ToolConfidence: 90}, true, 65},
		{"floor", Observation{Name: "x", Version: "1.0 (Ubuntu)", ToolConfidence: 1}, false, 0},
	}
	for _, c := range cases {
		if got := Confidence(parse(c.o), c.o, c.global); got != c.want {
			t.Errorf("%s: %d, want %d", c.name, got, c.want)
		}
	}
}
