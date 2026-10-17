package config

import "testing"

func TestInternalAPIBindAddress(t *testing.T) {
	base := InternalAPIConfig{CertFile: "c", KeyFile: "k", ClientCAFile: "ca", JWTPublicKeysFile: "j", JWTIssuer: "openctem-cloud"}
	for addr, wantErr := range map[string]bool{
		"10.0.0.5:9443": false, "172.16.4.2:9443": false, "192.168.8.10:9443": false, "127.0.0.1:9443": false,
		"[::1]:9443": false, "[fd00::5]:9443": false,
		":9443": true, "0.0.0.0:9443": true, "[::]:9443": true, "no-port": true,
		"203.0.113.7:9443": true, "8.8.8.8:9443": true, "[2001:db8::1]:9443": true,
		"169.254.10.1:9443": true, "[fe80::1]:9443": true, "core.example.com:9443": true, "localhost:9443": true,
	} {
		c := base
		c.Addr = addr
		if err := c.validate(); (err != nil) != wantErr {
			t.Errorf("%s: err=%v, want error %v", addr, err, wantErr)
		}
	}
	c := base
	for _, addr := range []string{":9443", "203.0.113.7:9443", "core.example.com:9443"} {
		c.Addr, c.AllowAllInterfaces = addr, true
		if err := c.validate(); err != nil {
			t.Fatalf("%s explicitly allowed: %v", addr, err)
		}
	}
	c = base
	c.Addr, c.CertFile = "10.0.0.5:9443", ""
	if err := c.validate(); err == nil {
		t.Fatal("a missing file must be refused")
	}
	if err := (InternalAPIConfig{}).validate(); err != nil {
		t.Fatalf("off: %v", err)
	}
}
