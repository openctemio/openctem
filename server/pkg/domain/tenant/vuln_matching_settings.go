package tenant

import (
	"fmt"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Vulnerability matching defaults (RFC-066 §9).
const (
	DefaultVulnMatchMinConfidence = 65
	DefaultVulnMatchMinSeverity   = "high"
	DefaultVulnMatchMinEPSS       = 0.1
	MaxVulnMatchMutedProducts     = 100
)

// VulnMatchingSettings is the organization's policy for findings created by
// inventory vulnerability matching (RFC-066 §9). Matches below the policy
// are still shown on the asset; the policy decides which become findings.
//
// Enabled is true for organizations created after the feature shipped
// (DefaultSettings) and false for existing ones until an admin turns it on.
type VulnMatchingSettings struct {
	Enabled bool `json:"enabled"`
	// MinConfidence (0-100); 0 = DefaultVulnMatchMinConfidence.
	MinConfidence int `json:"min_confidence,omitempty"`
	// MinSeverity is critical, high, medium or low; "" = high. A CVE in KEV,
	// or with an EPSS score of at least DefaultVulnMatchMinEPSS, passes
	// regardless.
	MinSeverity string `json:"min_severity,omitempty"`
	// IncludeDistroBuilds lets distribution builds (whose upstream version
	// hides back-ported fixes) become findings.
	IncludeDistroBuilds bool `json:"include_distro_builds"`
	// InternetFacingOnly limits findings to internet-facing assets.
	InternetFacingOnly bool `json:"internet_facing_only"`
	// MutedProducts are product names never turned into findings.
	MutedProducts []string `json:"muted_products,omitempty"`
}

var vulnMatchSeverities = map[string]int{"low": 1, "medium": 2, "high": 3, "critical": 4}

// Validate checks the bounds.
func (s VulnMatchingSettings) Validate() error {
	if s.MinConfidence < 0 || s.MinConfidence > 100 {
		return fmt.Errorf("%w: min_confidence must be between 0 and 100", shared.ErrValidation)
	}
	if s.MinSeverity != "" {
		if _, ok := vulnMatchSeverities[s.MinSeverity]; !ok {
			return fmt.Errorf("%w: min_severity must be critical, high, medium or low", shared.ErrValidation)
		}
	}
	if len(s.MutedProducts) > MaxVulnMatchMutedProducts {
		return fmt.Errorf("%w: at most %d muted products", shared.ErrValidation, MaxVulnMatchMutedProducts)
	}
	for _, p := range s.MutedProducts {
		if strings.TrimSpace(p) == "" || len(p) > 200 {
			return fmt.Errorf("%w: a muted product name must be 1-200 characters", shared.ErrValidation)
		}
	}
	return nil
}

// EffectiveMinConfidence returns the confidence threshold.
func (s VulnMatchingSettings) EffectiveMinConfidence() int {
	if s.MinConfidence <= 0 {
		return DefaultVulnMatchMinConfidence
	}
	return s.MinConfidence
}

// SeverityPasses reports whether a CVE severity reaches the threshold.
func (s VulnMatchingSettings) SeverityPasses(severity string) bool {
	minSev := s.MinSeverity
	if minSev == "" {
		minSev = DefaultVulnMatchMinSeverity
	}
	return vulnMatchSeverities[strings.ToLower(severity)] >= vulnMatchSeverities[minSev]
}

// IsMuted reports whether a product name is muted.
func (s VulnMatchingSettings) IsMuted(product string) bool {
	for _, p := range s.MutedProducts {
		if strings.EqualFold(strings.TrimSpace(p), strings.TrimSpace(product)) {
			return true
		}
	}
	return false
}
