package config

import (
	"testing"
	"time"
)

func TestValidateSystem(t *testing.T) {
	for _, tc := range []struct {
		name string
		s    SystemConfig
		ok   bool
	}{
		{"defaults", SystemConfig{}, true},
		{"http health url", SystemConfig{WebHealthURL: "http://web:3000/api/health"}, true},
		{"file scheme", SystemConfig{WebHealthURL: "file:///etc/passwd"}, false},
		{"credentials", SystemConfig{GatewayHealthURL: "https://u:p@gw/health"}, false},
		{"no host", SystemConfig{GatewayHealthURL: "http://"}, false},
		{"fast interval", SystemConfig{WatchInterval: time.Second}, false},
		{"interval", SystemConfig{WatchInterval: 5 * time.Minute}, true},
	} {
		c := &Config{System: tc.s}
		if err := c.validateSystem(); (err == nil) != tc.ok {
			t.Errorf("%s: err = %v, want ok=%v", tc.name, err, tc.ok)
		}
	}
}
