package scope

import (
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// An exclusion that can never match is refused at creation instead of being
// shown as protecting its target while it excludes nothing.
func TestNewExclusion_RefusesPatternsThatMatchNothing(t *testing.T) {
	tenant := shared.NewID()
	bad := []struct {
		typ     ExclusionType
		pattern string
	}{
		{ExclusionTypeIPRange, "10.0.0.9-10.0.0.1"},
		{ExclusionTypeCIDR, "10.0.0.0/33"},
		{ExclusionTypeCIDR, "not-a-network"},
		{ExclusionTypeIPAddress, "10.0.0.0/24"},
		{ExclusionTypeIPAddress, "10.0.0.999"},
		{ExclusionTypeDomain, "https://admin.example.com"},
		{ExclusionTypeDomain, "admin.example.com/login"},
		{ExclusionTypeURL, "admin.example.com/login"},
	}
	for _, c := range bad {
		if _, err := NewExclusion(tenant, c.typ, c.pattern, "reason", nil, ""); err == nil {
			t.Errorf("%s %q accepted", c.typ, c.pattern)
		} else if !errors.Is(err, shared.ErrValidation) {
			t.Errorf("%s %q: %v, want a validation error", c.typ, c.pattern, err)
		}
	}
	good := []struct {
		typ     ExclusionType
		pattern string
	}{
		{ExclusionTypeIPRange, "10.0.0.1-10.0.0.9"},
		{ExclusionTypeCIDR, "10.0.0.0/24"},
		{ExclusionTypeCIDR, "2001:db8::/48"},
		{ExclusionTypeIPAddress, "10.0.0.5"},
		{ExclusionTypeIPAddress, "2001:db8::1"},
		{ExclusionTypeDomain, "admin.example.com"},
		{ExclusionTypeDomain, "*.staging.example.com"},
		{ExclusionTypeURL, "https://admin.example.com/*"},
		{ExclusionTypeScanner, "nuclei"},
	}
	for _, c := range good {
		if _, err := NewExclusion(tenant, c.typ, c.pattern, "reason", nil, ""); err != nil {
			t.Errorf("%s %q refused: %v", c.typ, c.pattern, err)
		}
	}
}
