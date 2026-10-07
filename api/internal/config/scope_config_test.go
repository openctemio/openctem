package config

import "testing"

// SCOPE_ACTIVE_PROOF (RFC-054 §8.1): unset is platform_sensors for a
// self-service (SaaS) install and off otherwise; anything else fails startup.
func TestLoad_ScopeActiveProof(t *testing.T) {
	cases := []struct {
		env, creation, want string
		wantErr             bool
	}{
		{"", "", ScopeProofOff, false},
		{"", TenantCreationSelfService, ScopeProofPlatformSensors, false},
		{"all", "", ScopeProofAll, false},
		{"off", TenantCreationSelfService, ScopeProofOff, false},
		{"platform_sensors", "", ScopeProofPlatformSensors, false},
		{"everything", "", "", true},
	}
	for _, c := range cases {
		t.Setenv("SCOPE_ACTIVE_PROOF", c.env)
		t.Setenv("TENANT_CREATION_MODE", c.creation)
		cfg, err := Load()
		if c.wantErr {
			if err == nil {
				t.Errorf("SCOPE_ACTIVE_PROOF=%q: Load succeeded, want an error", c.env)
			}
			continue
		}
		if err != nil {
			t.Fatalf("SCOPE_ACTIVE_PROOF=%q: Load: %v", c.env, err)
		}
		if cfg.Scope.ActiveProof != c.want {
			t.Errorf("SCOPE_ACTIVE_PROOF=%q TENANT_CREATION_MODE=%q: %q, want %q", c.env, c.creation, cfg.Scope.ActiveProof, c.want)
		}
	}
	t.Setenv("SCOPE_ACTIVE_PROOF", "")
	t.Setenv("SCOPE_DENY_EXTRA", "203.0.113.0/24, platform.example")
	t.Setenv("SCOPE_MAX_PUBLIC_CIDR_V4", "20")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Scope.DenyExtra) != 2 || cfg.Scope.MaxPublicCIDRv4 != 20 || cfg.Scope.MaxPublicCIDRv6 != 32 {
		t.Fatalf("scope config = %+v", cfg.Scope)
	}
}
