package tenant

import (
	"encoding/json"
	"strings"
)

// Secrets kept in tenant settings are write-only. They are set through the
// owner-only settings endpoints (PATCH /tenants/{t}/settings/api for the
// webhook signing secret, the AI settings endpoint for the BYOK key) and are
// never read back: every response that carries the settings map goes through
// RedactSettings, which replaces each secret with a "<key>_configured" flag.
//
// Known secret keys today: api.webhook_secret and ai.api_key. The match is by
// name pattern rather than by that list, so a secret added to the settings
// later is redacted without anyone having to remember this function.

// secretSettingKeyMarkers are substrings that mark a settings key as secret.
var secretSettingKeyMarkers = []string{
	"secret", "password", "passwd", "api_key", "apikey", "private_key",
	"access_token", "refresh_token", "credential",
}

// ConfiguredSuffix is appended to a redacted key to form its flag.
const ConfiguredSuffix = "_configured"

// IsSecretSettingKey reports whether a settings key holds a secret.
func IsSecretSettingKey(key string) bool {
	k := strings.ToLower(key)
	if strings.HasSuffix(k, ConfiguredSuffix) {
		return false
	}
	for _, m := range secretSettingKeyMarkers {
		if strings.Contains(k, m) {
			return true
		}
	}
	return false
}

// RedactSettings returns a deep copy of a tenant settings map with every
// secret value removed and replaced by "<key>_configured": true/false. Only
// string (or null) values are treated as secrets, so flags such as
// api.api_key_enabled are kept. The input is not modified.
func RedactSettings(settings map[string]any) map[string]any {
	if settings == nil {
		return nil
	}
	// A JSON round trip turns typed values (structs stored with SetSetting)
	// into plain maps, so nested secrets are found whatever their Go type.
	raw, err := json.Marshal(settings)
	if err != nil {
		return map[string]any{}
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return map[string]any{}
	}
	redactSecretValues(out)
	return out
}

func redactSecretValues(m map[string]any) {
	for k, v := range m {
		switch val := v.(type) {
		case map[string]any:
			redactSecretValues(val)
		case []any:
			for _, item := range val {
				if child, ok := item.(map[string]any); ok {
					redactSecretValues(child)
				}
			}
		case string:
			if IsSecretSettingKey(k) {
				delete(m, k)
				m[k+ConfiguredSuffix] = val != ""
			}
		case nil:
			if IsSecretSettingKey(k) {
				delete(m, k)
				m[k+ConfiguredSuffix] = false
			}
		}
	}
}
