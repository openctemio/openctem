package coverage

import (
	"slices"
	"testing"

	covdom "github.com/openctemio/openctem/api/pkg/domain/coverage"
)

// enumerate.subdomains is planned (an active stage); an intrusive stage and
// a capability outside the catalog are not.
func TestPlannedCapabilities_IncludesActiveEnumeration(t *testing.T) {
	got := plannedCapabilities([]covdom.Rule{
		{Capability: "discover.subdomains"}, {Capability: "enumerate.subdomains"},
		{Capability: "dast.web"}, {Capability: "dns.email"}, {Capability: "enumerate.subdomains"},
	})
	if !slices.Equal(got, []string{"discover.subdomains", "enumerate.subdomains"}) {
		t.Fatalf("planned %v", got)
	}
}
