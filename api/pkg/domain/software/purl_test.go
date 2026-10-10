package software

import "testing"

func TestParsePURL(t *testing.T) {
	cases := []struct {
		in                   string
		typ, ns, name, ver   string
		canonical, base, err string
	}{
		{in: "pkg:npm/lodash@4.17.21", typ: "npm", name: "lodash", ver: "4.17.21", canonical: "pkg:npm/lodash@4.17.21", base: "pkg:npm/lodash"},
		{in: "pkg:npm/%40Angular/Core@17.0.0", typ: "npm", ns: "@angular", name: "core", ver: "17.0.0", canonical: "pkg:npm/@angular/core@17.0.0"},
		{in: "PKG:PyPI/Django_REST@3.0?x=1#sub/path", typ: "pypi", name: "django-rest", ver: "3.0", canonical: "pkg:pypi/django-rest@3.0"},
		{in: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", typ: "maven", ns: "org.apache.logging.log4j", name: "log4j-core", ver: "2.14.1"},
		{in: "pkg:golang/github.com/gin-gonic/gin@v1.9.1", typ: "golang", ns: "github.com/gin-gonic", name: "gin", ver: "v1.9.1"},
		{in: "pkg:deb/debian/openssl@3.0.11-1?arch=amd64&distro=debian-12", typ: "deb", ns: "debian", name: "openssl", ver: "3.0.11-1"},
		{in: "pkg:generic/thing", typ: "generic", name: "thing", canonical: "pkg:generic/thing"},
		{in: "pkg:npm/a%40b@1.0.0+build", typ: "npm", name: "a@b", ver: "1.0.0+build"},
		{in: "npm/lodash@1", err: "x"},
		{in: "pkg:npm", err: "x"},
		{in: "pkg:/lodash@1", err: "x"},
		{in: "pkg:1npm/lodash@1", err: "x"},
		{in: "pkg:npm/%zz@1", err: "x"},
	}
	for _, c := range cases {
		p, err := ParsePURL(c.in)
		if c.err != "" {
			if err == nil {
				t.Errorf("%q: want an error, got %+v", c.in, p)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q: %v", c.in, err)
			continue
		}
		if p.Type != c.typ || p.Namespace != c.ns || p.Name != c.name || p.Version != c.ver {
			t.Errorf("%q = %+v", c.in, p)
		}
		if c.canonical != "" && p.String() != c.canonical {
			t.Errorf("%q canonical = %q, want %q", c.in, p.String(), c.canonical)
		}
		if c.base != "" && p.Base() != c.base {
			t.Errorf("%q base = %q", c.in, p.Base())
		}
	}
}

func TestPURLLimits(t *testing.T) {
	long := make([]byte, MaxPURLName+1)
	for i := range long {
		long[i] = 'a'
	}
	if _, err := ParsePURL("pkg:npm/" + string(long) + "@1"); err == nil {
		t.Error("an over-long name must be refused")
	}
}

func TestDistroQualifier(t *testing.T) {
	p, _ := ParsePURL("pkg:deb/debian/openssl@3.0.11-1?arch=amd64&distro=debian-12")
	if q := p.DistroQualifier(); q != "debian-12/amd64" {
		t.Errorf("qualifier = %q", q)
	}
	n, _ := ParsePURL("pkg:npm/x@1?arch=amd64")
	if n.DistroQualifier() != "" {
		t.Error("only OS packages carry a distribution qualifier")
	}
}

func TestSyntheticPURL(t *testing.T) {
	cases := map[[3]string]string{
		{"pip", "Requests_Lib", "2.0"}:               "pkg:pypi/requests-lib@2.0",
		{"maven", "org.slf4j:slf4j-api", "2.0.9"}:    "pkg:maven/org.slf4j/slf4j-api@2.0.9",
		{"gomod", "github.com/pkg/errors", "v0.9.1"}: "pkg:golang/github.com/pkg/errors@v0.9.1",
		{"npm", "@scope/Pkg", "1.0.0"}:               "pkg:npm/@scope/pkg@1.0.0",
		{"", "thing", ""}:                            "pkg:generic/thing",
		{"cargo", "serde", "1.0.0"}:                  "pkg:cargo/serde@1.0.0",
	}
	for in, want := range cases {
		p, err := SyntheticPURL(in[0], in[1], in[2])
		if err != nil || p.String() != want {
			t.Errorf("SyntheticPURL%v = %q %v, want %q", in, p.String(), err, want)
		}
	}
	if _, err := SyntheticPURL("npm", "  ", "1"); err == nil {
		t.Error("an empty name must be refused")
	}
}

func TestEcosystemMapping(t *testing.T) {
	for typ, eco := range map[string]string{"golang": "go", "gem": "rubygems", "npm": "npm", "weird": "weird"} {
		if got := EcosystemForType(typ); got != eco {
			t.Errorf("EcosystemForType(%q) = %q", typ, got)
		}
	}
	for in, want := range map[string]string{"go": "golang", "rubygems": "gem", "NPM": "npm", "golang": "golang", "oci": "oci", "zzz": "generic"} {
		if got := PURLTypeForFilter(in); got != want {
			t.Errorf("PURLTypeForFilter(%q) = %q, want %q", in, got, want)
		}
	}
	if SchemeForType("pypi") != "pep440" || SchemeForType("gem") != "generic" {
		t.Error("scheme mapping")
	}
}
