package config

import (
	"strings"
	"testing"
)

// The CAPTCHA needs the secret (the API requires a token) and the site key
// (the web renders the check) together: one alone blocks every sign-up or
// checks nothing.
func TestValidateAuth_CaptchaPair(t *testing.T) {
	for name, tc := range map[string]struct {
		secret, site string
		wantErr      bool
	}{
		"neither":          {},
		"both":             {secret: "s", site: "k"},
		"secret only":      {secret: "s", wantErr: true},
		"site key only":    {site: "k", wantErr: true},
		"blank secret too": {secret: "  ", site: "k", wantErr: true},
	} {
		t.Run(name, func(t *testing.T) {
			c := minimalValidConfig()
			c.Auth.CaptchaTurnstileSecret = tc.secret
			c.Auth.CaptchaTurnstileSiteKey = tc.site
			err := c.validateAuth()
			if tc.wantErr != (err != nil && strings.Contains(err.Error(), "CAPTCHA_TURNSTILE")) {
				t.Fatalf("validateAuth = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}
