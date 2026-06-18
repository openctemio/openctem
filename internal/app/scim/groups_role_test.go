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
			if got := effectiveRole(tc.groups); got != tc.want {
				t.Errorf("effectiveRole(%v) = %q, want %q", tc.groups, got, tc.want)
			}
		})
	}
}
