package config

import "testing"

// SCAN_ZONE_RESOLVER: unset is a public resolver on a self-service (SaaS)
// install, so tenants never resolve names through the platform's internal
// DNS, and the platform's own resolver otherwise.
func TestLoad_ScanZoneResolver(t *testing.T) {
	cases := []struct{ env, creation, want string }{
		{"", "", ScanZoneResolverSystem},
		{"", TenantCreationSelfService, DefaultPublicZoneResolver},
		{"system", TenantCreationSelfService, ScanZoneResolverSystem},
		{"9.9.9.9:53", "", "9.9.9.9:53"},
	}
	for _, c := range cases {
		t.Setenv("SCAN_ZONE_RESOLVER", c.env)
		t.Setenv("TENANT_CREATION_MODE", c.creation)
		cfg, err := Load()
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if cfg.Scope.ZoneResolver != c.want {
			t.Errorf("SCAN_ZONE_RESOLVER=%q TENANT_CREATION_MODE=%q: %q, want %q", c.env, c.creation, cfg.Scope.ZoneResolver, c.want)
		}
	}
}
