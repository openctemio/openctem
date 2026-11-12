package softwarematch

import (
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/edgeaddr"
)

func TestHostedBy(t *testing.T) {
	c := edgeaddr.Default()
	for name, tc := range map[string]struct {
		f    HostFacts
		want string
	}{
		"name through a provider host":      {HostFacts{Name: "promo.acme.example", CNAME: "dns.ladipage.com"}, "LadiPage"},
		"web origin through a provider":     {HostFacts{Name: "https://promo.acme.example:443", CNAME: "dns.ladipage.com"}, "LadiPage"},
		"address in a published edge range": {HostFacts{Name: "104.16.0.1:443/tcp"}, "Cloudflare"},
		"address only provider names reach": {HostFacts{Name: "203.0.113.114:22/tcp", NameCNAMEs: []string{"dns.ladipage.com"}}, "LadiPage"},
		"address one own name reaches too":  {HostFacts{Name: "203.0.113.114:22/tcp", NameCNAMEs: []string{"dns.ladipage.com", ""}}, ""},
		"address no name reaches":           {HostFacts{Name: "203.0.113.114"}, ""},
		"own name":                          {HostFacts{Name: "www.acme.example", Addresses: []string{"198.51.100.7"}}, ""},
		"service the record names a CDN on": {HostFacts{Name: "shop.acme.example:443", CDN: "cloudflare"}, "Cloudflare"},
		"empty":                             {HostFacts{}, ""},
	} {
		if got := HostedBy(c, tc.f); got != tc.want {
			t.Errorf("%s: %q, want %q", name, got, tc.want)
		}
	}
	if HostedBy(nil, HostFacts{Name: "104.16.0.1"}) != "" {
		t.Error("nil classifier attributed something")
	}
}
