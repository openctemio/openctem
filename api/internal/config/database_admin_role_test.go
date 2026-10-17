package config

import "testing"

func TestDatabaseAdminRole(t *testing.T) {
	base := DatabaseConfig{User: "app", Password: "app-pass", MaxOpenConns: 50, MaxIdleConns: 10}

	if base.AdminConfig() != nil {
		t.Fatal("no DB_ADMIN_USER: want no console pool")
	}
	if err := base.validateAdminRole(); err != nil {
		t.Fatalf("single role: %v", err)
	}

	ok := base
	ok.AdminUser, ok.AdminPassword = "console", "console-pass"
	if err := ok.validateAdminRole(); err != nil {
		t.Fatalf("valid console role: %v", err)
	}
	a := ok.AdminConfig()
	if a == nil || a.User != "console" || a.Password != "console-pass" || a.MaxOpenConns > 5 {
		t.Fatalf("console pool config: %+v", a)
	}
	if ok.User != "app" || ok.Password != "app-pass" {
		t.Fatal("AdminConfig changed the app settings")
	}

	for name, mut := range map[string]func(*DatabaseConfig){
		"password without user": func(c *DatabaseConfig) { c.AdminUser = "" },
		"same role as the app":  func(c *DatabaseConfig) { c.AdminUser = "app" },
		"no password":           func(c *DatabaseConfig) { c.AdminPassword = "" },
		"app's password":        func(c *DatabaseConfig) { c.AdminPassword = "app-pass" },
	} {
		c := ok
		mut(&c)
		if err := c.validateAdminRole(); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}
