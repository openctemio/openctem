package authzdoc

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/platformauthz"
)

// The tenant permission reference (what the tenant web app bundles and the
// tenant API serves) never carries the platform console's authorization: no
// platform permission, no platform role, no console route (RFC-134).
func TestTenantReferenceCarriesNoPlatformAuthorization(t *testing.T) {
	ref := buildRef(t).WithoutConsoleRoutes()
	for _, p := range ref.Permissions {
		if platformauthz.IsPlatformKey(p.ID) {
			t.Errorf("tenant reference lists platform permission %s", p.ID)
		}
	}
	b, err := json.Marshal(ref)
	if err != nil {
		t.Fatal(err)
	}
	body := string(b)
	leaks := []string{ConsolePathPrefix, "super_admin", "ops_admin"}
	for _, r := range platformauthz.BuiltinRoles() {
		leaks = append(leaks, `"`+string(r.Key)+`"`)
	}
	for _, d := range platformauthz.Catalog() {
		leaks = append(leaks, string(d.Key))
	}
	for _, leak := range leaks {
		if strings.Contains(body, leak) {
			t.Errorf("tenant reference mentions %q", leak)
		}
	}
}
