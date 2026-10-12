package scope

import "testing"

// A scan target is often a whole network ("10.0.0.0/16"), not one address.
// An exclusion must stop it whenever the two share any address: the scanner is
// handed the target string as-is, so a /16 that contains an excluded /24 would
// scan the excluded /24.
func TestMatchesExclusionPattern_IPSets(t *testing.T) {
	tests := []struct {
		name    string
		exType  ExclusionType
		pattern string
		value   string
		want    bool
	}{
		// CIDR exclusion vs single addresses (already worked).
		{"cidr contains ip", ExclusionTypeCIDR, "10.0.0.0/24", "10.0.0.5", true},
		{"cidr misses ip", ExclusionTypeCIDR, "10.0.0.0/24", "10.0.1.5", false},

		// CIDR exclusion vs CIDR targets.
		{"target supernet of exclusion", ExclusionTypeCIDR, "10.0.0.0/24", "10.0.0.0/16", true},
		{"target subnet of exclusion", ExclusionTypeCIDR, "10.0.0.0/24", "10.0.0.0/25", true},
		{"target equal to exclusion", ExclusionTypeCIDR, "10.0.0.0/24", "10.0.0.0/24", true},
		{"target disjoint", ExclusionTypeCIDR, "10.0.0.0/24", "10.0.1.0/24", false},
		{"target cidr with host bits", ExclusionTypeCIDR, "10.0.0.0/24", "10.0.0.9/30", true},

		// IP-range exclusions.
		{"range contains ip across octet", ExclusionTypeIPRange, "10.0.0.250-10.0.1.5", "10.0.1.0", true},
		{"range misses ip", ExclusionTypeIPRange, "10.0.0.250-10.0.1.5", "10.0.1.6", false},
		{"range overlaps cidr target", ExclusionTypeIPRange, "10.0.0.250-10.0.1.5", "10.0.1.0/24", true},
		{"range vs disjoint cidr", ExclusionTypeIPRange, "10.0.0.250-10.0.1.5", "10.0.2.0/24", false},
		{"cidr excl vs range target", ExclusionTypeCIDR, "10.0.1.0/24", "10.0.0.250-10.0.1.5", true},

		// Single-address exclusions vs networks.
		{"ip excl inside cidr target", ExclusionTypeIPAddress, "10.0.0.5", "10.0.0.0/24", true},
		{"ip excl outside cidr target", ExclusionTypeIPAddress, "10.0.0.5", "10.0.1.0/24", false},
		{"ip excl exact", ExclusionTypeIPAddress, "10.0.0.5", "10.0.0.5", true},
		{"ip excl other ip", ExclusionTypeIPAddress, "10.0.0.5", "10.0.0.6", false},
		{"ipv6 excl spelled differently", ExclusionTypeIPAddress, "2001:db8::1", "2001:db8:0:0::1", true},

		// IPv6.
		{"v6 cidr vs v6 supernet", ExclusionTypeCIDR, "2001:db8:1::/48", "2001:db8::/32", true},
		{"v6 cidr vs v6 subnet", ExclusionTypeCIDR, "2001:db8::/32", "2001:db8:1::/64", true},
		{"v6 cidr vs disjoint", ExclusionTypeCIDR, "2001:db8::/32", "2001:db9::/32", false},
		{"v4-mapped v6 address", ExclusionTypeCIDR, "10.0.0.0/24", "::ffff:10.0.0.5", true},

		// Families never match each other; garbage never matches.
		{"v4 excl vs v6 target", ExclusionTypeCIDR, "10.0.0.0/8", "2001:db8::/32", false},
		{"not an ip", ExclusionTypeCIDR, "10.0.0.0/24", "example.com", false},
		{"bad pattern", ExclusionTypeCIDR, "10.0.0.0/33", "10.0.0.1", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := MatchesExclusionPattern(tt.exType, tt.pattern, tt.value); got != tt.want {
				t.Errorf("MatchesExclusionPattern(%s, %q, %q) = %v, want %v", tt.exType, tt.pattern, tt.value, got, tt.want)
			}
		})
	}
}

// Targets keep containment semantics: an asset is in a CIDR/range target only
// when ALL of it lies inside. Fixes the byte-wise range comparison too.
func TestMatchesPattern_IPSets(t *testing.T) {
	tests := []struct {
		name    string
		tType   TargetType
		pattern string
		value   string
		want    bool
	}{
		{"ip in cidr", TargetTypeCIDR, "10.0.0.0/16", "10.0.3.4", true},
		{"subnet in cidr", TargetTypeCIDR, "10.0.0.0/16", "10.0.3.0/24", true},
		{"supernet not in cidr", TargetTypeCIDR, "10.0.0.0/24", "10.0.0.0/16", false},
		{"range target across octet", TargetTypeIPRange, "10.0.0.250-10.0.1.5", "10.0.1.0", true},
		{"range target misses", TargetTypeIPRange, "10.0.0.250-10.0.1.5", "10.0.0.249", false},
		{"v6 in cidr", TargetTypeCIDR, "2001:db8::/32", "2001:db8::42", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := MatchesPattern(tt.tType, tt.pattern, tt.value); got != tt.want {
				t.Errorf("MatchesPattern(%s, %q, %q) = %v, want %v", tt.tType, tt.pattern, tt.value, got, tt.want)
			}
		})
	}
}
