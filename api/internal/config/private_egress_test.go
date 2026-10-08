package config

import (
	"strings"
	"testing"
)

// The process-wide allow-private switch would open the platform's own network
// to every tenant; outside APP_ENV=development the server refuses to start.
func TestValidate_PrivateEgress(t *testing.T) {
	for name, tc := range map[string]struct {
		env, all, cidrs string
		wantErr         string
	}{
		"unset, production":           {env: EnvProduction},
		"switch in development":       {env: envDevelopment, all: "1"},
		"switch in production":        {env: EnvProduction, all: "1", wantErr: "OPENCTEM_HTTPSEC_ALLOW_PRIVATE=1"},
		"switch in staging":           {env: "staging", all: "1", wantErr: "APP_ENV=development"},
		"switch with a typo":          {env: envDevelopment, all: "true", wantErr: "must be empty"},
		"named range in production":   {env: EnvProduction, cidrs: "10.20.0.0/16, fd12:3456::/48"},
		"public range in production":  {env: EnvProduction, cidrs: "203.0.113.0/24", wantErr: "not inside a private range"},
		"wider than a private range":  {env: EnvProduction, cidrs: "10.0.0.0/7", wantErr: "not inside a private range"},
		"loopback is not allowlisted": {env: envDevelopment, cidrs: "127.0.0.0/8", wantErr: "not inside a private range"},
		"not a CIDR":                  {env: EnvProduction, cidrs: "10.0.0.5", wantErr: "not a CIDR"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("OPENCTEM_HTTPSEC_ALLOW_PRIVATE", tc.all)
			t.Setenv("OPENCTEM_HTTPSEC_ALLOW_PRIVATE_CIDRS", tc.cidrs)
			c := minimalValidConfig()
			c.App.Env = tc.env
			c.Encryption.Key = "ab00112233445566778899aabbccddeeff00112233445566778899aabbccddee"
			err := c.validateBasic()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("validateBasic: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("validateBasic = %v, want an error containing %q", err, tc.wantErr)
			}
		})
	}
}
