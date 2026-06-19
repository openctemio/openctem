package scim

import "testing"

func TestEffectiveRole(t *testing.T) {
	tests := []struct {
		name   string
		groups []string
		want   string
	}{
		{"no groups → member default", nil, "member"},
		{"non-role groups → member default", []string{"Engineering", "All Staff"}, "member"},
		{"viewer only", []string{"viewer"}, "viewer"},
		{"member only", []string{"member"}, "member"},
		{"admin only", []string{"admin"}, "admin"},
		{"admin wins over viewer", []string{"viewer", "admin"}, "admin"},
		{"admin wins over member", []string{"member", "admin"}, "admin"},
		{"member wins over viewer", []string{"viewer", "member"}, "member"},
		{"case-insensitive", []string{"ADMIN"}, "admin"},
		{"owner is never mapped", []string{"owner"}, "member"},
		{"role group mixed with custom", []string{"Engineering", "viewer"}, "viewer"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := effectiveRole(tc.groups, nil); got != tc.want {
				t.Errorf("effectiveRole(%v, nil) = %q, want %q", tc.groups, got, tc.want)
			}
		})
	}
}

func TestEffectiveRole_WithMappings(t *testing.T) {
	mappings := map[string]string{
		"acme-openctem-admins":  "admin",
		"acme-openctem-readers": "viewer",
	}
	tests := []struct {
		name   string
		groups []string
		want   string
	}{
		{"custom name mapped to admin", []string{"Acme-OpenCTEM-Admins"}, "admin"},
		{"custom name mapped to viewer", []string{"Acme-OpenCTEM-Readers"}, "viewer"},
		{"case-insensitive custom mapping", []string{"ACME-OPENCTEM-ADMINS"}, "admin"},
		{"mapping wins highest across groups", []string{"Acme-OpenCTEM-Readers", "Acme-OpenCTEM-Admins"}, "admin"},
		{"unmapped falls back to name-match", []string{"viewer"}, "viewer"},
		{"unmapped custom group → member default", []string{"Engineering"}, "member"},
		{"mapping + name-match combine", []string{"Engineering", "Acme-OpenCTEM-Readers"}, "viewer"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := effectiveRole(tc.groups, mappings); got != tc.want {
				t.Errorf("effectiveRole(%v, mappings) = %q, want %q", tc.groups, got, tc.want)
			}
		})
	}
}
