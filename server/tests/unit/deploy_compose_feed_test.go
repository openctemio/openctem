package unit

import (
	"os"
	"testing"

	"gopkg.in/yaml.v3"
)

// The vulnerability feed settings of .env reach the api container only if the
// Compose file passes them. Each is passed with an empty default, so an unset
// value behaves exactly as before.
func TestDeployComposePassesFeedSettingsToAPI(t *testing.T) {
	raw, err := os.ReadFile("../../deploy/docker-compose.yml")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Services map[string]struct {
			Environment map[string]string `yaml:"environment"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	env := f.Services["api"].Environment
	for _, name := range []string{
		"VULNFEED_BASE_URL", "VULNFEED_MIRRORS", "VULNFEED_BUNDLE_DIR", "VULNFEED_ROOT_KEY_ID",
		"OPENCTEM_HTTPSEC_FEED_PROXY", "OPENCTEM_HTTPSEC_FEED_NO_PROXY", "OPENCTEM_HTTPSEC_ALLOW_PRIVATE_CIDRS",
	} {
		want := "${" + name + ":-}"
		if got, ok := env[name]; !ok || got != want {
			t.Errorf("api environment %s = %q (present %v), want %q", name, got, ok, want)
		}
	}
}
