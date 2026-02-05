package fetchers

import (
	"fmt"
	"net"
	"testing"
)

func TestValidateURL_SSRFPrevention(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		// Valid public URLs
		{
			name:    "valid public https URL",
			url:     "https://example.com/templates.zip",
			wantErr: false,
		},
		{
			name:    "valid public http URL",
			url:     "http://example.com/templates.tar.gz",
			wantErr: false,
		},
		{
			name:    "valid github raw URL",
			url:     "https://raw.githubusercontent.com/org/repo/main/templates/custom.yaml",
			wantErr: false,
		},

		// Blocked schemes
		{
			name:    "ftp scheme blocked",
			url:     "ftp://example.com/file.yaml",
			wantErr: true,
		},
		{
			name:    "file scheme blocked",
			url:     "file:///etc/passwd",
			wantErr: true,
		},
		{
			name:    "gopher scheme blocked",
			url:     "gopher://example.com/",
			wantErr: true,
		},

		// Loopback addresses (SSRF)
		{
			name:    "localhost blocked",
			url:     "http://localhost/admin",
			wantErr: true,
		},
		{
			name:    "127.0.0.1 blocked",
			url:     "http://127.0.0.1/internal",
			wantErr: true,
		},
		{
			name:    "127.x.x.x blocked",
			url:     "http://127.0.0.2/internal",
			wantErr: true,
		},

		// Private IP ranges (SSRF)
		{
			name:    "10.x.x.x blocked",
			url:     "http://10.0.0.1/internal",
			wantErr: true,
		},
		{
			name:    "172.16.x.x blocked",
			url:     "http://172.16.0.1/internal",
			wantErr: true,
		},
		{
			name:    "192.168.x.x blocked",
			url:     "http://192.168.1.1/admin",
			wantErr: true,
		},

		// Cloud metadata endpoints (critical SSRF)
		{
			name:    "AWS metadata blocked",
			url:     "http://169.254.169.254/latest/meta-data/",
			wantErr: true,
		},
		{
			name:    "metadata hostname blocked",
			url:     "http://metadata/computeMetadata/v1/",
			wantErr: true,
		},
		{
			name:    "GCP metadata blocked",
			url:     "http://metadata.google.internal/computeMetadata/v1/",
			wantErr: true,
		},

		// Link-local addresses
		{
			name:    "link-local blocked",
			url:     "http://169.254.1.1/",
			wantErr: true,
		},

		// Invalid URLs
		{
			name:    "empty URL",
			url:     "",
			wantErr: true,
		},
		{
			name:    "malformed URL",
			url:     "://invalid",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateURL(tt.url)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateURL(%q) error = %v, wantErr %v", tt.url, err, tt.wantErr)
			}
		})
	}
}

func TestSanitizeArchivePath(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		wantSafe string
		wantErr  bool
	}{
		// Safe paths
		{
			name:     "simple filename",
			path:     "template.yaml",
			wantSafe: "template.yaml",
			wantErr:  false,
		},
		{
			name:     "nested path flattened",
			path:     "templates/nuclei/sqli.yaml",
			wantSafe: "sqli.yaml",
			wantErr:  false,
		},
		{
			name:     "deeply nested",
			path:     "a/b/c/d/e/file.yaml",
			wantSafe: "file.yaml",
			wantErr:  false,
		},

		// Path traversal attacks
		{
			name:    "parent directory escape",
			path:    "../../../etc/passwd",
			wantErr: true,
		},
		{
			name:    "encoded traversal",
			path:    "templates/../../../etc/shadow",
			wantErr: true,
		},
		{
			name:    "double dot at start",
			path:    "..hidden",
			wantErr: true,
		},

		// Absolute paths
		{
			name:    "unix absolute path",
			path:    "/etc/passwd",
			wantErr: true,
		},

		// Windows-style paths
		{
			name:    "backslash path",
			path:    "templates\\nuclei\\test.yaml",
			wantErr: true,
		},
		{
			name:    "windows absolute",
			path:    "C:\\Windows\\System32\\config",
			wantErr: true,
		},

		// Path length
		{
			name:    "path too long",
			path:    string(make([]byte, maxPathLength+1)),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := sanitizeArchivePath(tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("sanitizeArchivePath(%q) error = %v, wantErr %v", tt.path, err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.wantSafe {
				t.Errorf("sanitizeArchivePath(%q) = %q, want %q", tt.path, got, tt.wantSafe)
			}
		})
	}
}

func TestIsIPBlocked(t *testing.T) {
	tests := []struct {
		name    string
		ip      string
		blocked bool
	}{
		// Loopback
		{"loopback v4", "127.0.0.1", true},
		{"loopback v4 other", "127.255.255.255", true},
		{"loopback v6", "::1", true},

		// Private ranges
		{"private 10.x", "10.0.0.1", true},
		{"private 172.16.x", "172.16.0.1", true},
		{"private 172.31.x", "172.31.255.255", true},
		{"private 192.168.x", "192.168.1.1", true},

		// Link-local (AWS metadata)
		{"link-local", "169.254.169.254", true},
		{"link-local other", "169.254.0.1", true},

		// Public IPs (should NOT be blocked)
		{"public google dns", "8.8.8.8", false},
		{"public cloudflare", "1.1.1.1", false},
		{"public aws", "52.94.76.1", false},

		// Edge cases at boundary
		{"just outside 10.x", "11.0.0.1", false},
		{"just outside 172.16", "172.15.255.255", false},
		{"just outside 192.168", "192.169.0.1", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := parseIPHelper(tt.ip)
			if ip == nil {
				t.Fatalf("failed to parse IP: %s", tt.ip)
			}
			got := isIPBlocked(ip)
			if got != tt.blocked {
				t.Errorf("isIPBlocked(%s) = %v, want %v", tt.ip, got, tt.blocked)
			}
		})
	}
}

func TestNewHTTPFetcher_SSRFValidation(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{
			name:    "valid public URL",
			url:     "https://example.com/templates.zip",
			wantErr: false,
		},
		{
			name:    "localhost blocked at creation",
			url:     "http://localhost:8080/internal",
			wantErr: true,
		},
		{
			name:    "private IP blocked at creation",
			url:     "http://10.0.0.1/internal",
			wantErr: true,
		},
		{
			name:    "metadata endpoint blocked at creation",
			url:     "http://169.254.169.254/latest/meta-data/",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := HTTPConfig{URL: tt.url}
			_, err := NewHTTPFetcher(cfg)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewHTTPFetcher(%q) error = %v, wantErr %v", tt.url, err, tt.wantErr)
			}
		})
	}
}

// parseIPHelper is a helper to parse IP strings in tests
func parseIPHelper(s string) net.IP {
	// Simple parsing for test purposes
	var a, b, c, d int
	n, _ := fmt.Sscanf(s, "%d.%d.%d.%d", &a, &b, &c, &d)
	if n == 4 {
		return net.IPv4(byte(a), byte(b), byte(c), byte(d))
	}
	// Handle IPv6 loopback
	if s == "::1" {
		return net.ParseIP(s)
	}
	return net.ParseIP(s)
}
