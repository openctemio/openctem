package validator

import (
	"strings"
	"testing"
)

func TestValidateWebhookURL(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		// Valid URLs
		{
			name:    "valid https URL",
			url:     "https://example.com/webhook",
			wantErr: false,
		},
		{
			name:    "valid http URL",
			url:     "http://api.service.com/hook",
			wantErr: false,
		},
		{
			name:    "empty string is allowed",
			url:     "",
			wantErr: false,
		},

		// Invalid schemes
		{
			name:    "file scheme blocked",
			url:     "file:///etc/passwd",
			wantErr: true,
		},
		{
			name:    "gopher scheme blocked",
			url:     "gopher://evil.com",
			wantErr: true,
		},
		{
			name:    "javascript scheme blocked",
			url:     "javascript:alert(1)",
			wantErr: true,
		},

		// Localhost and loopback
		{
			name:    "localhost blocked",
			url:     "http://localhost/admin",
			wantErr: true,
		},
		{
			name:    "loopback IP blocked",
			url:     "http://127.0.0.1/admin",
			wantErr: true,
		},

		// Private/internal IPs
		{
			name:    "private IP 10.x blocked",
			url:     "http://10.0.0.1/internal",
			wantErr: true,
		},
		{
			name:    "private IP 192.168.x blocked",
			url:     "http://192.168.1.1/internal",
			wantErr: true,
		},
		{
			name:    "private IP 172.16.x blocked",
			url:     "http://172.16.0.1/internal",
			wantErr: true,
		},
		{
			name:    "link-local AWS metadata blocked",
			url:     "http://169.254.169.254/metadata",
			wantErr: true,
		},

		// Malformed URLs
		{
			name:    "not a URL",
			url:     "not-a-url",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateWebhookURL(tt.url)
			if tt.wantErr && err == nil {
				t.Errorf("ValidateWebhookURL(%q) expected error, got nil", tt.url)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("ValidateWebhookURL(%q) unexpected error: %v", tt.url, err)
			}
		})
	}
}

func TestValidateWebhookURL_ErrorMessages(t *testing.T) {
	tests := []struct {
		name        string
		url         string
		wantContain string
	}{
		{
			name:        "file scheme error mentions scheme",
			url:         "file:///etc/passwd",
			wantContain: "scheme",
		},
		{
			name:        "localhost error mentions localhost",
			url:         "http://localhost/admin",
			wantContain: "localhost",
		},
		{
			name:        "internal IP error mentions internal",
			url:         "http://10.0.0.1/internal",
			wantContain: "internal",
		},
		{
			name:        "loopback error mentions internal or localhost",
			url:         "http://127.0.0.1/admin",
			wantContain: "internal",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateWebhookURL(tt.url)
			if err == nil {
				t.Fatalf("ValidateWebhookURL(%q) expected error, got nil", tt.url)
			}
			if !strings.Contains(err.Error(), tt.wantContain) {
				t.Errorf("ValidateWebhookURL(%q) error = %q, want to contain %q",
					tt.url, err.Error(), tt.wantContain)
			}
		})
	}
}
