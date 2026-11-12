package handler

import (
	"strings"
	"testing"
)

func TestIsValidHostHeader(t *testing.T) {
	tests := []struct {
		name  string
		host  string
		valid bool
	}{
		// Valid hosts
		{
			name:  "simple domain",
			host:  "example.com",
			valid: true,
		},
		{
			name:  "subdomain",
			host:  "api.example.com",
			valid: true,
		},
		{
			name:  "domain with port",
			host:  "example.com:8080",
			valid: true,
		},
		{
			name:  "IP with port",
			host:  "192.168.1.1:443",
			valid: true,
		},
		{
			name:  "IP address only",
			host:  "10.0.0.1",
			valid: true,
		},
		{
			name:  "domain with hyphen",
			host:  "my-api.example.com",
			valid: true,
		},

		// Invalid hosts
		{
			name:  "empty string",
			host:  "",
			valid: false,
		},
		{
			name:  "CRLF injection",
			host:  "example.com\r\nX-Injected: true",
			valid: false,
		},
		{
			name:  "newline injection",
			host:  "example.com\nX-Injected: true",
			valid: false,
		},
		{
			name:  "javascript scheme",
			host:  "javascript:alert(1)",
			valid: false,
		},
		{
			name:  "XSS in host",
			host:  "<script>alert(1)</script>",
			valid: false,
		},
		{
			name:  "slash in host",
			host:  "example.com/path",
			valid: false,
		},
		{
			name:  "space in host",
			host:  "example .com",
			valid: false,
		},
		{
			name:  "at sign in host",
			host:  "user@example.com",
			valid: false,
		},
		{
			name:  "very long host exceeds 253 chars",
			host:  strings.Repeat("a", 254),
			valid: false,
		},
		{
			name:  "host at exactly 253 chars is valid",
			host:  strings.Repeat("a", 253),
			valid: true,
		},
		{
			name:  "null byte injection",
			host:  "example.com\x00evil",
			valid: false,
		},
		{
			name:  "tab character",
			host:  "example.com\tevil",
			valid: false,
		},
		{
			name:  "semicolon",
			host:  "example.com;evil",
			valid: false,
		},
		{
			name:  "unicode character",
			host:  "example\u00e9.com",
			valid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isValidHostHeader(tt.host)
			if got != tt.valid {
				t.Errorf("isValidHostHeader(%q) = %v, want %v", tt.host, got, tt.valid)
			}
		})
	}
}
