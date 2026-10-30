package edgeaddr

import (
	"net/netip"
	"testing"
)

func TestAddress(t *testing.T) {
	c := Default()
	for _, tc := range []struct {
		name, addr, cdn, org string
		class                Class
		provider             string
		basis                Basis
	}{
		{"cloudflare published range", "104.16.1.1", "", "", Edge, "Cloudflare", BasisRange},
		{"cloudflare v6 range", "2606:4700::1", "", "", Edge, "Cloudflare", BasisRange},
		{"mapped v4 in range", "::ffff:104.16.1.1", "", "", Edge, "Cloudflare", BasisRange},
		{"fastly published range", "151.101.1.1", "", "", Edge, "Fastly", BasisRange},
		{"range wins over the network name", "151.101.2.2", "", "Amazon.com, Inc.", Edge, "Fastly", BasisRange},
		{"record names a CDN", "198.51.100.1", "cloudflare", "", Edge, "Cloudflare", BasisCDN},
		{"record names an unknown CDN", "198.51.100.1", "examplecdn", "", Edge, "examplecdn", BasisCDN},
		{"akamai by network", "198.51.100.2", "", "Akamai Technologies, Inc.", Edge, "Akamai", BasisNetwork},
		{"imperva by asn handle", "198.51.100.3", "", "INCAPSULA", Edge, "Imperva", BasisNetwork},
		{"cloudflare asn handle", "198.51.100.4", "", "CLOUDFLARENET", Edge, "Cloudflare", BasisNetwork},
		{"saas hosting", "198.51.100.5", "", "Vercel Inc", SaaSHosting, "Vercel", BasisNetwork},
		{"github pages", "198.51.100.6", "", "GitHub, Inc.", SaaSHosting, "GitHub", BasisNetwork},
		// A dedicated customer address inside a provider's network: only
		// published edge ranges are edge, the rest is dedicated with a label.
		{"cloud static address", "198.51.100.7", "", "AMAZON-02", Dedicated, "Amazon", BasisNetwork},
		{"vps", "198.51.100.8", "", "Hetzner Online GmbH", Dedicated, "Hetzner", BasisNetwork},
		{"word prefix only", "198.51.100.9", "", "Dawson Hosting Ltd", Dedicated, "", BasisNone},
		{"unknown", "198.51.100.10", "", "", Dedicated, "", BasisNone},
		{"own network", "203.0.113.1", "", "Acme Corp", Dedicated, "", BasisNone},
		{"not an address", "www.acme.example", "", "", Dedicated, "", BasisNone},
	} {
		got := c.Address(tc.addr, tc.cdn, tc.org)
		if got.Class != tc.class || got.Provider != tc.provider || got.Basis != tc.basis {
			t.Errorf("%s: got %+v", tc.name, got)
		}
		if got.Shared() != (tc.class != Dedicated) {
			t.Errorf("%s: Shared() = %v", tc.name, got.Shared())
		}
	}
}

func TestHost(t *testing.T) {
	c := Default()
	for _, tc := range []struct {
		host     string
		class    Class
		provider string
	}{
		{"d111.cloudfront.net", Edge, "Amazon CloudFront"},
		{"my-lb-1.eu-west-1.elb.amazonaws.com.", CloudShared, "Amazon"},
		{"acme.github.io", SaaSHosting, "GitHub"},
		{"shop.myshopify.com", SaaSHosting, "Shopify"},
		{"github.io.acme.example", Dedicated, ""},
		{"www.acme.example", Dedicated, ""},
	} {
		got := c.Host(tc.host)
		if got.Class != tc.class || got.Provider != tc.provider {
			t.Errorf("%s: got %+v", tc.host, got)
		}
	}
}

func TestNewRefusesABadDataset(t *testing.T) {
	for name, d := range map[string]Dataset{
		"bad class":  {Orgs: []OrgEntry{{Match: "x", Provider: "X", Class: "cdn"}}},
		"bad prefix": {Ranges: []RangeEntry{{Provider: "X", Class: Edge, Prefixes: []string{"300.0.0.0/8"}}}},
		"no match":   {Orgs: []OrgEntry{{Match: " ", Provider: "X", Class: Edge}}},
		"no suffix":  {Apexes: []ApexEntry{{Suffix: ".", Provider: "X", Class: Edge}}},
	} {
		if _, err := New(d); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if Default().Version() == "" {
		t.Error("built-in dataset has no version")
	}
}

func TestRange(t *testing.T) {
	c := Default()
	p := func(s string) netip.Addr { return netip.MustParseAddr(s) }
	for _, tc := range []struct {
		name     string
		lo, hi   string
		class    Class
		provider string
	}{
		{"one cloudflare address", "104.16.1.1", "104.16.1.1", Edge, "Cloudflare"},
		{"cloudflare /24", "104.16.1.0", "104.16.1.255", Edge, "Cloudflare"},
		{"fastly v6", "2a04:4e42::", "2a04:4e42::ff", Edge, "Fastly"},
		{"overlaps the edge only in part", "104.15.255.0", "104.16.0.255", Dedicated, ""},
		{"own range", "203.0.113.0", "203.0.113.255", Dedicated, ""},
		{"reversed", "104.16.1.9", "104.16.1.1", Dedicated, ""},
	} {
		got := c.Range(p(tc.lo), p(tc.hi))
		if got.Class != tc.class || got.Provider != tc.provider {
			t.Errorf("%s: got %+v", tc.name, got)
		}
	}
	if got := c.Range(netip.Addr{}, p("104.16.1.1")); got.Class != Dedicated || got.Provider != "" {
		t.Errorf("invalid end: got %+v", got)
	}
}

func TestName(t *testing.T) {
	c := Default()
	for _, tc := range []struct {
		name, host    string
		cnames, addrs []string
		class         Class
		provider      string
	}{
		{"cname to cloudfront", "app.acme.example", []string{"d111.cloudfront.net"}, []string{"198.51.100.1"}, Edge, "Amazon CloudFront"},
		{"cname to akamai", "www.acme.example", []string{"www.acme.example.edgekey.net"}, nil, Edge, "Akamai"},
		{"every address cloudflare", "api.acme.example", nil, []string{"104.16.1.1", "172.64.1.1"}, Edge, "Cloudflare"},
		{"one direct address", "mix.acme.example", nil, []string{"104.16.1.1", "203.0.113.5"}, Dedicated, ""},
		{"cloudflare by network name only is not enough", "x.acme.example", nil, []string{"198.51.100.4"}, Dedicated, ""},
		{"the name is a hosting page", "acme.github.io", nil, nil, SaaSHosting, "GitHub"},
		{"cloud load balancer", "lb.acme.example", []string{"x-1.eu-west-1.elb.amazonaws.com"}, nil, CloudShared, "Amazon"},
		{"nothing known", "intranet.acme.example", nil, nil, Dedicated, ""},
	} {
		got := c.Name(tc.host, tc.cnames, tc.addrs)
		if got.Class != tc.class || got.Provider != tc.provider {
			t.Errorf("%s: got %+v", tc.name, got)
		}
	}
}
