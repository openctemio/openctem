package unit

import (
	"testing"

	"github.com/openctemio/api/internal/infra/http/handler"
	"github.com/stretchr/testify/assert"
)

func TestParsePropertiesFilter(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect map[string][]string
	}{
		{"empty", "", nil},
		{"single", "vendor:Cisco", map[string][]string{"vendor": {"Cisco"}}},
		{"multiple keys", "vendor:Cisco,model:ASA", map[string][]string{"vendor": {"Cisco"}, "model": {"ASA"}}},
		{"with spaces", " vendor : Cisco , model : ASA ", map[string][]string{"vendor": {"Cisco"}, "model": {"ASA"}}},
		{"value with colon", "url:https://example.com", map[string][]string{"url": {"https://example.com"}}},
		{"empty key", ":value", nil},
		{"empty value", "key:", nil},
		{"no colon", "justtext", nil},
		{"max 10 keys", "a:1,b:2,c:3,d:4,e:5,f:6,g:7,h:8,i:9,j:10,k:11", map[string][]string{
			"a": {"1"}, "b": {"2"}, "c": {"3"}, "d": {"4"}, "e": {"5"},
			"f": {"6"}, "g": {"7"}, "h": {"8"}, "i": {"9"}, "j": {"10"},
		}},
		{"multi-value same key", "os:linux,os:windows", map[string][]string{"os": {"linux", "windows"}}},
		{"invalid key chars", "ven-dor:Cisco", nil},
		{"sql injection key", "'; DROP TABLE--:val", nil},
		{"unicode key", "vendör:Cisco", nil},
		{"underscore key", "firmware_version:1.0", map[string][]string{"firmware_version": {"1.0"}}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := handler.ParsePropertiesFilter(tt.input)
			if tt.expect == nil {
				assert.True(t, len(result) == 0, "expected nil or empty, got %v", result)
			} else {
				assert.Equal(t, tt.expect, result)
			}
		})
	}
}
