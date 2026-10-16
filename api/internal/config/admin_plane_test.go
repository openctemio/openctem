package config

import "testing"

func TestParseAdminAllowedCIDRs(t *testing.T) {
	p, err := ParseAdminAllowedCIDRs([]string{"10.0.0.0/8", " 203.0.113.7 ", "2001:db8::1", "192.168.1.9/16"})
	if err != nil || len(p) != 4 || p[1].String() != "203.0.113.7/32" || p[2].String() != "2001:db8::1/128" || p[3].String() != "192.168.0.0/16" {
		t.Fatalf("parsed %v, %v", p, err)
	}
	for _, bad := range [][]string{{}, {""}, {"10.0.0.0/33"}, {"intranet"}} {
		if _, err := ParseAdminAllowedCIDRs(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	c := AdminPlaneConfig{AllowedCIDRs: DefaultAdminAllowedCIDRs}
	cfg := &Config{AdminPlane: c}
	if err := cfg.validateAdminPlane(); err != nil || cfg.AdminPlane.AllowsEveryNetwork() || len(cfg.AdminPlane.AllowedPrefixes()) != 6 {
		t.Fatalf("defaults: %v %v", err, cfg.AdminPlane.AllowedPrefixes())
	}
	cfg.AdminPlane.AllowedCIDRs = []string{"0.0.0.0/0", "::/0"}
	if err := cfg.validateAdminPlane(); err != nil || !cfg.AdminPlane.AllowsEveryNetwork() {
		t.Fatalf("open: %v", err)
	}
}
