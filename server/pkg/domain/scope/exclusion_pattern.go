package scope

import (
	"fmt"
	"strings"
)

// ValidateExclusionPattern refuses an exclusion pattern its matcher can
// never match: a reversed range, a /33 network, a URL in a domain
// exclusion. Such an exclusion was accepted, shown as protecting the
// target, and excluded nothing. Types whose matcher compares text
// (repository, finding type, scanner) and path rules (checked by their
// web rule) are left to their own checks.
func ValidateExclusionPattern(t ExclusionType, pattern string) error {
	p := strings.TrimSpace(pattern)
	if p == "" {
		return fmt.Errorf("%w: pattern cannot be empty", ErrInvalidPattern)
	}
	if len(p) > 500 {
		return fmt.Errorf("%w (max 500 characters)", ErrPatternTooLong)
	}
	switch t {
	case ExclusionTypeDomain, ExclusionTypeSubdomain:
		return validateDomainPattern(p)
	case ExclusionTypeIPAddress:
		set, ok := parseIPSet(strings.Trim(p, "[]"))
		if !ok || set.lo != set.hi || strings.ContainsAny(p, "/-") {
			return fmt.Errorf("%w: not an IP address", ErrInvalidPattern)
		}
	case ExclusionTypeIPRange, ExclusionTypeCIDR:
		if _, ok := parseIPSet(p); !ok {
			return fmt.Errorf("%w: not a CIDR block or a first-last IP range with first <= last", ErrInvalidPattern)
		}
	case ExclusionTypeURL:
		return validateURLPattern(p)
	}
	return nil
}
