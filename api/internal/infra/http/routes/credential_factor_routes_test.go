package routes

import (
	"os"
	"strings"
	"testing"
)

// Every route that mints a credential carries requireCredentialFactor, so a
// person the organization or the platform floor covers needs a second factor
// before creating an API key, a sensor token or an integration secret, even
// during their sign-in grace period.
func TestCredentialRoutesRequireFactor(t *testing.T) {
	want := map[string][]string{
		"misc.go": {
			`r.POST("/", h.Create, middleware.Require(permission.IntegrationsManage)`,
			`r.POST("/notifications", h.CreateNotification`,
			`r.PUT("/{id}", h.Update, middleware.Require(permission.IntegrationsManage)`,
			`r.PUT("/{id}/jira-webhook/secret"`,
			`r.PUT("/{id}/notification", h.UpdateNotification`,
			`r.POST("/", h.Create, middleware.Require(permission.APIKeysWrite)`,
		},
		"access_control.go": {`r.POST("/{id}/api-keys", h.CreateKey`},
		"scanning.go": {
			`r.POST("/", h.Create, middleware.Require(permission.SensorsWrite)`,
			`r.POST("/{id}/regenerate-key"`,
			`r.POST("/", h.Create, middleware.Require(permission.SecretStoreWrite)`,
			`r.PUT("/{id}", h.Update, middleware.Require(permission.SecretStoreWrite)`,
			`r.POST("/{id}/rotate", h.Rotate, middleware.Require(permission.SecretStoreWrite)`,
		},
		"sensor_pairing.go": {`r.POST("/enrollment-tokens", h.CreateEnrollmentToken`},
	}
	for file, prefixes := range want {
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(string(raw), "\n")
		for _, prefix := range prefixes {
			found := false
			for _, ln := range lines {
				if strings.Contains(ln, prefix) {
					found = true
					if !strings.Contains(ln, "requireCredentialFactor()") {
						t.Errorf("%s: %q does not require a second factor", file, strings.TrimSpace(ln))
					}
				}
			}
			if !found {
				t.Errorf("%s: route %q not found (update this test with the route)", file, prefix)
			}
		}
	}
}
