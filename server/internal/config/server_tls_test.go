package config

import "testing"

// The API listener terminates TLS only with both files; one of them alone
// is a configuration mistake, refused at start.
func TestServerTLSFilesSetTogether(t *testing.T) {
	for name, tc := range map[string]struct {
		cert, key string
		ok, tls   bool
	}{
		"plain HTTP (default)": {ok: true},
		"both":                 {cert: "/certs/tls.crt", key: "/certs/tls.key", ok: true, tls: true},
		"cert only":            {cert: "/certs/tls.crt"},
		"key only":             {key: "/certs/tls.key"},
	} {
		t.Run(name, func(t *testing.T) {
			c := minimalValidConfig()
			c.Server.TLSCertFile, c.Server.TLSKeyFile = tc.cert, tc.key
			if err := c.validateBasic(); (err == nil) != tc.ok {
				t.Fatalf("validateBasic = %v, want ok=%v", err, tc.ok)
			}
			if tc.ok && c.Server.TLSEnabled() != tc.tls {
				t.Fatalf("TLSEnabled = %v, want %v", c.Server.TLSEnabled(), tc.tls)
			}
		})
	}
}
