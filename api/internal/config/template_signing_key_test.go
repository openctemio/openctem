package config

import (
	"strings"
	"testing"
)

// APP_TEMPLATE_SIGNING_KEY: a malformed key, or the encryption key reused,
// stops the server instead of signing with something unintended.
func TestValidate_TemplateSigningKey(t *testing.T) {
	c := minimalValidConfig()
	c.Encryption.TemplateSigningKey = strings.Repeat("ab", 32)
	if err := c.Validate(); err != nil {
		t.Fatalf("a valid hex key was refused: %v", err)
	}
	for name, key := range map[string]string{
		"too short": "abcd",
		"not hex":   strings.Repeat("zz", 32),
	} {
		c := minimalValidConfig()
		c.Encryption.TemplateSigningKey = key
		err := c.Validate()
		if err == nil || !strings.Contains(err.Error(), "APP_TEMPLATE_SIGNING_KEY") || strings.Contains(err.Error(), key) {
			t.Errorf("%s: err = %v; want a refusal naming the variable, not the key", name, err)
		}
	}
	c = minimalValidConfig()
	c.Encryption.Key = strings.Repeat("cd", 32)
	c.Encryption.TemplateSigningKey = c.Encryption.Key
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "must differ") {
		t.Errorf("reused encryption key: %v", err)
	}
}
