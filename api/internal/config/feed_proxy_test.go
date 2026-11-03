package config

import (
	"strings"
	"testing"
)

// A feed proxy setting the clients would ignore stops the start, and the
// refusal never quotes the proxy password.
func TestValidate_FeedProxy(t *testing.T) {
	for name, tc := range map[string]struct{ proxy, wantErr string }{
		"unset":             {},
		"http proxy":        {proxy: "http://proxy.corp.example:3128"},
		"https with creds":  {proxy: "https://feed:s3cr3t@10.20.0.5:8443"},
		"socks refused":     {proxy: "socks5://feed:s3cr3t@p:1080", wantErr: "http:// or https://"},
		"no scheme refused": {proxy: "proxy.corp.example:3128", wantErr: "OPENCTEM_HTTPSEC_FEED_PROXY"},
		"path refused":      {proxy: "http://feed:s3cr3t@p:3128/x", wantErr: "no path"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("OPENCTEM_HTTPSEC_FEED_PROXY", tc.proxy)
			t.Setenv("OPENCTEM_HTTPSEC_FEED_NO_PROXY", "")
			c := minimalValidConfig()
			c.App.Env = EnvProduction
			c.Encryption.Key = "ab00112233445566778899aabbccddeeff00112233445566778899aabbccddee"
			c.Encryption.FingerprintKey = c.Encryption.Key
			err := c.validateBasic()
			if tc.wantErr == "" {
				if err != nil && strings.Contains(err.Error(), "FEED_PROXY") {
					t.Fatalf("refused: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("want %q, got %v", tc.wantErr, err)
			}
			if strings.Contains(err.Error(), "s3cr3t") {
				t.Fatalf("refusal quotes the password: %v", err)
			}
		})
	}
}
