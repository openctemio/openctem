package software_test

import (
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/software"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// The catalog's package identity and the finding identity must name a
// package the same way: otherwise a package and the findings on it split
// into two names (for example pkg:deb/debian/OpenSSL in the catalog and
// pkg:deb/debian/openssl on the finding).
func TestPackageIdentityMatchesFindingIdentity(t *testing.T) {
	inputs := []string{
		"pkg:npm/%40Angular/Core@17.0.0",
		"pkg:pypi/Django_REST@3.0",
		"pkg:maven/org.Apache.Logging.Log4j/Log4j-Core@2.14.1",
		"pkg:golang/github.com/Gin-Gonic/Gin@v1.9.1",
		"pkg:deb/Debian/OpenSSL@3.0.11-1",
		"pkg:apk/Alpine/BusyBox@1.36.1-r2",
		"pkg:alpm/Arch/Pacman@6.0.1-1",
		"pkg:hex/Phoenix@1.7.0",
		"pkg:rpm/Fedora/Curl@8.0.1",
		"pkg:github/Package-URL/Purl-Spec@1.0",
		"pkg:bitbucket/Birkenfeld/Pygments-Main@244fd47",
		"pkg:composer/Laravel/Framework@10.0.0",
		"pkg:gem/Rails@7.1.0",
		"pkg:nuget/Newtonsoft.Json@13.0.1",
		"pkg:cargo/Serde@1.0.0",
	}
	for _, in := range inputs {
		p, err := software.ParsePURL(in)
		if err != nil {
			t.Fatalf("%q: %v", in, err)
		}
		if got, want := p.Base(), vulnerability.CanonicalPURLIdentity(in); got != want {
			t.Errorf("%q: catalog identity %q, finding identity %q", in, got, want)
		}
	}
}
