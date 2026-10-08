package component

import "testing"

// Trivy fs components carry a package URL and no ecosystem label; they were
// stored as "other". The ecosystem now comes from the label, else the PURL.
func TestResolveEcosystem(t *testing.T) {
	cases := []struct {
		label, purl string
		want        Ecosystem
	}{
		{"", "pkg:npm/%40babel/core@7.24.0", EcosystemNPM},
		{"", "pkg:golang/github.com/gin-gonic/gin@v1.9.1", EcosystemGo},
		{"", "pkg:pypi/requests@2.31.0", EcosystemPyPI},
		{"", "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", EcosystemMaven},
		{"", "pkg:cargo/serde@1.0.0", EcosystemCargo},
		{"", "pkg:nuget/Newtonsoft.Json@13.0.1", EcosystemNuGet},
		{"", "pkg:gem/rails@7.0.0", EcosystemRubyGems},
		{"", "pkg:composer/laravel/framework@10.0.0", EcosystemComposer},
		{"", "pkg:swift/github.com/apple/swift-nio@2.0.0", EcosystemSwiftPM},
		{"", "pkg:deb/debian/openssl@3.0.11", EcosystemOther},
		{"", "not-a-purl", EcosystemOther},
		{"", "", EcosystemOther},
		{"gomod", "", EcosystemGo},
		{"jar", "", EcosystemMaven},
		{"rustbinary", "", EcosystemCargo},
		{"uv", "", EcosystemPyPI},
		{"dotnet-core", "", EcosystemNuGet},
		// A known label wins over the PURL.
		{"npm", "pkg:pypi/requests@2.31.0", EcosystemNPM},
		// An unknown label falls back to the PURL.
		{"some-new-type", "pkg:cargo/serde@1.0.0", EcosystemCargo},
	}
	for _, c := range cases {
		if got := ResolveEcosystem(c.label, c.purl); got != c.want {
			t.Errorf("ResolveEcosystem(%q, %q) = %q, want %q", c.label, c.purl, got, c.want)
		}
	}
}
