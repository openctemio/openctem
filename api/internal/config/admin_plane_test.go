package config

import "testing"

func TestParseAdminAllowedCIDRs(t *testing.T) {
	p, err := ParseAdminAllowedCIDRs([]string{"10.0.0.0/8", " 203.0.113.7 ", "2001:db8::1", "192.168.1.9/16"})
	if err != nil || len(p) != 4 || p[1].String() != "203.0.113.7/32" || p[2].String() != "2001:db8::1/128" || p[3].String() != "192.168.0.0/16" {
		t.Fatalf("parsed %v, %v", p, err)
	}
	if p, err := ParseAdminAllowedCIDRs([]string{"10.0.0.0/8 192.168.0.0/16", " fc00::/7 "}); err != nil || len(p) != 3 {
		t.Fatalf("space-separated: %v, %v", p, err)
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

func TestAdminListenAddr(t *testing.T) {
	for addr, ok := range map[string]bool{
		"127.0.0.1:8081": true, "10.0.0.5:8081": true, "172.30.80.12:8081": true, "192.168.1.2:8081": true, "[fd00::1]:8081": true, "[::1]:8081": true,
		":8081": false, "0.0.0.0:8081": false, "[::]:8081": false, "203.0.113.5:8081": false, "169.254.1.1:8081": false, "api:8081": false, "8081": false,
	} {
		err := checkAdminListenAddr(addr, false)
		if (err == nil) != ok {
			t.Errorf("%s: err=%v, want ok=%v", addr, err, ok)
		}
	}
	if err := checkAdminListenAddr(":8081", true); err != nil {
		t.Errorf("allow-all: %v", err)
	}
	if err := checkAdminListenAddr("8081", true); err == nil {
		t.Error("not host:port must fail even with allow-all")
	}
}

// OPENCTEM_PLANE: a tenant process holds no console credentials and opens no
// console listener; an admin process needs the console role and a private
// main listener (or the explicit all-interfaces opt-in).
func TestPlaneValidation(t *testing.T) {
	base := func(plane string) *Config {
		return &Config{
			Server:     ServerConfig{Host: "10.0.0.7", Port: 8080},
			Database:   DatabaseConfig{User: "app"},
			AdminPlane: AdminPlaneConfig{Plane: plane, AllowedCIDRs: DefaultAdminAllowedCIDRs},
		}
	}
	cases := []struct {
		name   string
		cfg    func() *Config
		wantOK bool
	}{
		{"default is all", func() *Config { return base("") }, true},
		{"all", func() *Config { return base(PlaneAll) }, true},
		{"unknown", func() *Config { return base("console") }, false},
		{"tenant", func() *Config { return base(PlaneTenant) }, true},
		{"tenant with a console listener", func() *Config {
			c := base(PlaneTenant)
			c.AdminPlane.ListenAddr = "10.0.0.7:8081"
			return c
		}, false},
		{"tenant with console credentials", func() *Config {
			c := base(PlaneTenant)
			c.Database.AdminUser, c.Database.AdminPassword = "console", "pw"
			return c
		}, false},
		{"admin without the console role", func() *Config { return base(PlaneAdmin) }, false},
		{"admin", func() *Config {
			c := base(PlaneAdmin)
			c.Database.AdminUser, c.Database.AdminPassword = "console", "pw"
			return c
		}, true},
		{"admin with a second console listener", func() *Config {
			c := base(PlaneAdmin)
			c.Database.AdminUser, c.Database.AdminPassword = "console", "pw"
			c.AdminPlane.ListenAddr = "10.0.0.7:8081"
			return c
		}, false},
		{"admin on every interface", func() *Config {
			c := base(PlaneAdmin)
			c.Database.AdminUser, c.Database.AdminPassword = "console", "pw"
			c.Server.Host = "0.0.0.0"
			return c
		}, false},
		{"admin on every interface, opted in", func() *Config {
			c := base(PlaneAdmin)
			c.Database.AdminUser, c.Database.AdminPassword = "console", "pw"
			c.Server.Host = "0.0.0.0"
			c.AdminPlane.ListenAllowAllInterfaces = true
			return c
		}, true},
	}
	for _, tc := range cases {
		c := tc.cfg()
		err := c.validateAdminPlane()
		if (err == nil) != tc.wantOK {
			t.Errorf("%s: err=%v, want ok=%v", tc.name, err, tc.wantOK)
		}
	}
	c := base("")
	if err := c.validateAdminPlane(); err != nil || c.AdminPlane.Plane != PlaneAll || !c.AdminPlane.ServesConsole() || !c.AdminPlane.ServesTenant() {
		t.Fatalf("default plane: %v %+v", err, c.AdminPlane)
	}
	if (AdminPlaneConfig{Plane: PlaneTenant}).ServesConsole() || (AdminPlaneConfig{Plane: PlaneAdmin}).ServesTenant() {
		t.Fatal("tenant must not serve the console, admin must not serve tenants")
	}
}
