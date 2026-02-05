package validator

import (
	"testing"
)

func TestPropertiesValidator_ValidateProperties(t *testing.T) {
	v := NewPropertiesValidator()

	tests := []struct {
		name       string
		assetType  string
		properties map[string]any
		wantErrors int
	}{
		{
			name:      "valid domain properties",
			assetType: "domain",
			properties: map[string]any{
				"domain": map[string]any{
					"registrar":     "GoDaddy",
					"registered_at": "2020-01-01T00:00:00Z",
					"expires_at":    "2025-01-01T00:00:00Z",
					"dns_records": []any{
						map[string]any{"type": "A", "name": "@", "value": "1.2.3.4", "ttl": float64(300)},
					},
				},
			},
			wantErrors: 0,
		},
		{
			name:      "invalid domain timestamp",
			assetType: "domain",
			properties: map[string]any{
				"domain": map[string]any{
					"registered_at": "not-a-date",
				},
			},
			wantErrors: 1,
		},
		{
			name:      "invalid DNS record type",
			assetType: "domain",
			properties: map[string]any{
				"domain": map[string]any{
					"dns_records": []any{
						map[string]any{"type": "INVALID", "name": "@", "value": "1.2.3.4"},
					},
				},
			},
			wantErrors: 1,
		},
		{
			name:      "valid subdomain properties",
			assetType: "subdomain",
			properties: map[string]any{
				"parent_domain":    "example.com",
				"resolved_ips":     []any{"1.2.3.4", "5.6.7.8"},
				"discovery_source": "dns_enum",
			},
			wantErrors: 0,
		},
		{
			name:      "invalid subdomain IP",
			assetType: "subdomain",
			properties: map[string]any{
				"resolved_ips": []any{"not-an-ip"},
			},
			wantErrors: 1,
		},
		{
			name:      "invalid discovery source",
			assetType: "subdomain",
			properties: map[string]any{
				"discovery_source": "invalid_source",
			},
			wantErrors: 1,
		},
		{
			name:      "valid IP address properties",
			assetType: "ip_address",
			properties: map[string]any{
				"ip_address": map[string]any{
					"version": float64(4),
					"asn":     float64(15169),
					"country": "US",
					"ports": []any{
						map[string]any{"port": float64(80), "protocol": "tcp", "state": "open"},
						map[string]any{"port": float64(443), "protocol": "tcp", "state": "open"},
					},
					"geolocation": map[string]any{
						"latitude":  float64(37.7749),
						"longitude": float64(-122.4194),
					},
				},
			},
			wantErrors: 0,
		},
		{
			name:      "invalid IP version",
			assetType: "ip_address",
			properties: map[string]any{
				"ip_address": map[string]any{
					"version": float64(5),
				},
			},
			wantErrors: 1,
		},
		{
			name:      "invalid port number",
			assetType: "ip_address",
			properties: map[string]any{
				"ip_address": map[string]any{
					"ports": []any{
						map[string]any{"port": float64(70000), "protocol": "tcp"},
					},
				},
			},
			wantErrors: 1,
		},
		{
			name:      "invalid geolocation",
			assetType: "ip_address",
			properties: map[string]any{
				"ip_address": map[string]any{
					"geolocation": map[string]any{
						"latitude":  float64(100),
						"longitude": float64(-200),
					},
				},
			},
			wantErrors: 2,
		},
		{
			name:      "valid certificate properties",
			assetType: "certificate",
			properties: map[string]any{
				"certificate": map[string]any{
					"not_before": "2024-01-01T00:00:00Z",
					"not_after":  "2025-01-01T00:00:00Z",
					"key_size":   float64(2048),
				},
			},
			wantErrors: 0,
		},
		{
			name:      "invalid certificate key size",
			assetType: "certificate",
			properties: map[string]any{
				"certificate": map[string]any{
					"key_size": float64(512),
				},
			},
			wantErrors: 1,
		},
		{
			name:      "valid website properties",
			assetType: "website",
			properties: map[string]any{
				"url":           "https://example.com",
				"response_code": float64(200),
				"tls_version":   "TLS 1.3",
			},
			wantErrors: 0,
		},
		{
			name:      "invalid URL",
			assetType: "website",
			properties: map[string]any{
				"url": "not-a-url",
			},
			wantErrors: 1,
		},
		{
			name:      "invalid HTTP status code",
			assetType: "website",
			properties: map[string]any{
				"response_code": float64(999),
			},
			wantErrors: 1,
		},
		{
			name:      "valid API properties",
			assetType: "api",
			properties: map[string]any{
				"base_url":       "https://api.example.com/v1",
				"api_type":       "rest",
				"authentication": "oauth2",
			},
			wantErrors: 0,
		},
		{
			name:      "invalid API type",
			assetType: "api",
			properties: map[string]any{
				"api_type": "invalid",
			},
			wantErrors: 1,
		},
		{
			name:      "valid service properties",
			assetType: "service",
			properties: map[string]any{
				"service": map[string]any{
					"port":      float64(22),
					"transport": "tcp",
					"state":     "open",
				},
			},
			wantErrors: 0,
		},
		{
			name:      "invalid service port",
			assetType: "service",
			properties: map[string]any{
				"service": map[string]any{
					"port": float64(0),
				},
			},
			wantErrors: 1,
		},
		{
			name:      "valid cloud properties",
			assetType: "compute",
			properties: map[string]any{
				"provider":      "aws",
				"public_access": "private",
			},
			wantErrors: 0,
		},
		{
			name:      "invalid cloud provider",
			assetType: "storage",
			properties: map[string]any{
				"provider": "invalid_cloud",
			},
			wantErrors: 1,
		},
		{
			name:      "valid kubernetes cluster properties",
			assetType: "kubernetes_cluster",
			properties: map[string]any{
				"provider":   "eks",
				"node_count": float64(3),
			},
			wantErrors: 0,
		},
		{
			name:      "invalid kubernetes provider",
			assetType: "kubernetes_cluster",
			properties: map[string]any{
				"provider": "invalid",
			},
			wantErrors: 1,
		},
		{
			name:      "valid kubernetes namespace properties",
			assetType: "kubernetes_namespace",
			properties: map[string]any{
				"namespace": "default",
				"pod_count": float64(10),
			},
			wantErrors: 0,
		},
		{
			name:      "invalid kubernetes namespace name",
			assetType: "kubernetes_namespace",
			properties: map[string]any{
				"namespace": "Invalid_Name",
			},
			wantErrors: 1,
		},
		{
			name:      "valid network properties",
			assetType: "vpc",
			properties: map[string]any{
				"cidr_block": "10.0.0.0/16",
			},
			wantErrors: 0,
		},
		{
			name:      "invalid CIDR",
			assetType: "subnet",
			properties: map[string]any{
				"cidr_block": "invalid-cidr",
			},
			wantErrors: 1,
		},
		{
			name:      "valid IAM properties",
			assetType: "iam_user",
			properties: map[string]any{
				"provider":   "aws",
				"created_at": "2024-01-01T00:00:00Z",
			},
			wantErrors: 0,
		},
		{
			name:      "invalid IAM timestamp",
			assetType: "iam_role",
			properties: map[string]any{
				"created_at": "invalid-date",
			},
			wantErrors: 1,
		},
		{
			name:      "valid open port properties",
			assetType: "open_port",
			properties: map[string]any{
				"port":     float64(443),
				"protocol": "tcp",
				"state":    "open",
			},
			wantErrors: 0,
		},
		{
			name:      "invalid open port state",
			assetType: "open_port",
			properties: map[string]any{
				"state": "closed",
			},
			wantErrors: 1,
		},
		{
			name:      "property key too long",
			assetType: "other",
			properties: map[string]any{
				"this_is_a_very_long_property_key_that_exceeds_the_maximum_allowed_length_of_one_hundred_characters_and_should_fail_validation": "value",
			},
			wantErrors: 1,
		},
		{
			name:       "unknown asset type passes",
			assetType:  "unknown_type",
			properties: map[string]any{"custom": "value"},
			wantErrors: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errs := v.ValidateProperties(tt.assetType, tt.properties)
			if len(errs) != tt.wantErrors {
				t.Errorf("ValidateProperties() returned %d errors, want %d. Errors: %v", len(errs), tt.wantErrors, errs)
			}
		})
	}
}

func TestPropertiesValidator_MaxPropertiesCount(t *testing.T) {
	v := NewPropertiesValidator()

	// Create properties exceeding max count
	props := make(map[string]any)
	for i := 0; i < 150; i++ {
		props[string(rune('a'+i%26))+string(rune('0'+i/26))] = i
	}

	errs := v.ValidateProperties("other", props)
	if len(errs) == 0 {
		t.Error("expected error for exceeding max properties count")
	}

	found := false
	for _, err := range errs {
		if err.Path == "properties" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected error about properties count")
	}
}

func TestIsValidPropertyKey(t *testing.T) {
	tests := []struct {
		key  string
		want bool
	}{
		{"valid_key", true},
		{"validKey", true},
		{"key123", true},
		{"_invalid", false},
		{"123invalid", false},
		{"key-invalid", false},
		{"key.invalid", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			if got := isValidPropertyKey(tt.key); got != tt.want {
				t.Errorf("isValidPropertyKey(%q) = %v, want %v", tt.key, got, tt.want)
			}
		})
	}
}

func TestIsValidDomain(t *testing.T) {
	tests := []struct {
		domain string
		want   bool
	}{
		{"example.com", true},
		{"sub.example.com", true},
		{"my-domain.co.uk", true},
		{"invalid", false},
		{"invalid.", false},
		{".invalid", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			if got := isValidDomain(tt.domain); got != tt.want {
				t.Errorf("isValidDomain(%q) = %v, want %v", tt.domain, got, tt.want)
			}
		})
	}
}

func TestIsValidKubernetesName(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"default", true},
		{"kube-system", true},
		{"my-namespace", true},
		{"ns123", true},
		{"-invalid", false},
		{"Invalid", false},
		{"invalid_name", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isValidKubernetesName(tt.name); got != tt.want {
				t.Errorf("isValidKubernetesName(%q) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

func TestValidateJSON(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"valid JSON object", `{"key": "value"}`, false},
		{"valid nested JSON", `{"key": {"nested": 123}}`, false},
		{"invalid JSON", `{invalid}`, true},
		{"empty string", ``, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ValidateJSON([]byte(tt.input))
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateJSON() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
