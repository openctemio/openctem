package assetdomain

import (
	"reflect"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/edgeaddr"
)

func TestKeysStopAtRegistrableDomain(t *testing.T) {
	got := Keys([]string{"a.api.example.com.vn"})
	want := []string{"*.api.example.com.vn", "*.example.com.vn", "a.api.example.com.vn"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Keys = %v, want %v", got, want)
	}
	if got := Keys([]string{"example.com.vn"}); !reflect.DeepEqual(got, []string{"example.com.vn"}) {
		t.Fatalf("registrable name keys = %v", got)
	}
}

func TestNormalizeDomainFilter(t *testing.T) {
	ok := map[string]string{
		"Example.COM.vn.":   "example.com.vn",
		"*.Example.com":      "*.example.com",
		"vé.example.com.vn": "xn--v-bga.example.com.vn",
		"_dmarc.example.com": "_dmarc.example.com",
	}
	for in, want := range ok {
		if got, err := NormalizeDomainFilter(in); err != nil || got != want {
			t.Errorf("NormalizeDomainFilter(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"", "com", "com.vn", "*.com.vn", "10.0.0.1", "a%b.com", "a_b%.com", `a\b.com`, "*", "*.*.com", "https://x.com"} {
		if got, err := NormalizeDomainFilter(in); err == nil {
			t.Errorf("NormalizeDomainFilter(%q) = %q, accepted", in, got)
		}
	}
	if got := DomainFilterKeys("x.com"); !reflect.DeepEqual(got, []string{"x.com", "*.x.com"}) {
		t.Errorf("DomainFilterKeys(x.com) = %v", got)
	}
	if got := DomainFilterKeys("*.x.com"); !reflect.DeepEqual(got, []string{"*.x.com"}) {
		t.Errorf("DomainFilterKeys(*.x.com) = %v", got)
	}
}

func TestNamesByKind(t *testing.T) {
	c := edgeaddr.Default()
	cases := []struct {
		name string
		e    Evidence
		want []string
	}{
		{"certificate SANs, wildcard maps to its base", Evidence{Type: "certificate", Name: "ab12", Props: map[string]any{"subject_cn": "*.x.com", "sans": []any{"api.x.com", "*.x.com"}}}, []string{"api.x.com", "x.com"}},
		{"application URL host", Evidence{Type: "application", Name: "https://Portal.x.com:8443/login"}, []string{"portal.x.com"}},
		{"service by host name", Evidence{Type: "service", Name: "db.x.com:5432:tcp"}, []string{"db.x.com"}},
		{"address a name resolves to", Evidence{Type: "ip_address", Name: "203.0.113.5", Resolvers: []string{"api.x.com"}}, []string{"api.x.com"}},
		{"CDN address never", Evidence{Type: "ip_address", Name: "104.16.1.1", Resolvers: []string{"api.x.com"}}, []string{}},
		{"address with a CDN label never", Evidence{Type: "ip_address", Name: "203.0.113.6", Props: map[string]any{"cdn": "cloudflare"}, Resolvers: []string{"api.x.com"}}, []string{}},
		{"shared hosting never", Evidence{Type: "ip_address", Name: "203.0.113.7", Resolvers: []string{"a.x.com", "b.y.com", "c.z.org"}}, []string{}},
		{"service on an address, two hops", Evidence{Type: "service", Name: "203.0.113.5:443:tcp",
			Hosts: []Evidence{{Type: "ip_address", Name: "203.0.113.5", Resolvers: []string{"api.x.com"}}}}, []string{"api.x.com"}},
		{"repository has none", Evidence{Type: "repository", Name: "github.com/x/app"}, []string{}},
		{"public suffix is not a name", Evidence{Type: "domain", Name: "com.vn"}, []string{}},
	}
	for _, tc := range cases {
		got := Names(tc.e, c)
		if len(got) == 0 && len(tc.want) == 0 {
			continue
		}
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: Names = %v, want %v", tc.name, got, tc.want)
		}
	}
}
