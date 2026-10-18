package config

import (
	"os"
	"strings"
	"testing"
)

// SCOPE_ACTIVE_PROOF is retired (RFC-054 §8.1): the proof requirement is a
// console setting. A set variable, even empty, fails startup with the hint.
func TestLoad_ScopeActiveProofRetired(t *testing.T) {
	for _, v := range []string{"platform_sensors", "off", ""} {
		t.Setenv("SCOPE_ACTIVE_PROOF", v)
		_, err := Load()
		if err == nil || !strings.Contains(err.Error(), "SCOPE_ACTIVE_PROOF") || !strings.Contains(err.Error(), "Console > Scanning") {
			t.Fatalf("SCOPE_ACTIVE_PROOF=%q: Load error = %v, want the retired-variable hint", v, err)
		}
	}
	if err := os.Unsetenv("SCOPE_ACTIVE_PROOF"); err != nil {
		t.Fatal(err)
	}
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
