package config

import "testing"

func TestValidateAccountPortalURL(t *testing.T) {
	for _, ok := range []string{"", "https://account.example.com/billing"} {
		if err := validateAccountPortalURL(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{"http://account.example.com", "javascript:alert(1)", "/relative", "https://user:pw@example.com", "https://"} {
		if err := validateAccountPortalURL(bad); err == nil {
			t.Errorf("%q must be refused", bad)
		}
	}
}
