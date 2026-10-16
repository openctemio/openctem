package config

import "testing"

func TestInternalAPIBindAddress(t *testing.T) {
	base := InternalAPIConfig{CertFile: "c", KeyFile: "k", ClientCAFile: "ca", JWTPublicKeysFile: "j", JWTIssuer: "openctem-cloud"}
	for addr, wantErr := range map[string]bool{
		"10.0.0.5:9443": false, "127.0.0.1:9443": false, "[fd00::5]:9443": false,
		":9443": true, "0.0.0.0:9443": true, "[::]:9443": true, "no-port": true,
	} {
		c := base
		c.Addr = addr
		if err := c.validate(); (err != nil) != wantErr {
			t.Errorf("%s: err=%v, want error %v", addr, err, wantErr)
		}
	}
	c := base
	c.Addr, c.AllowAllInterfaces = ":9443", true
	if err := c.validate(); err != nil {
		t.Fatalf("explicitly allowed: %v", err)
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
