package sla

import (
	"fmt"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
)

// Policy represents an SLA policy for findings remediation.
type Policy struct {
	id                  shared.ID
	tenantID            shared.ID
	assetID             *shared.ID // nil = tenant default policy
	name                string
	description         string
	isDefault           bool
	criticalDays        int
	highDays            int
	mediumDays          int
	lowDays             int
	infoDays            int
	warningThresholdPct int
	escalationEnabled   bool
	escalationConfig    map[string]any
	isActive            bool
	createdAt           time.Time
	updatedAt           time.Time
}

// DefaultSLADays contains the default remediation days per severity.
var DefaultSLADays = map[string]int{
	"critical": 2,
	"high":     15,
	"medium":   30,
	"low":      60,
	"info":     90,
}

// NewPolicy creates a new SLA Policy with default values.
func NewPolicy(
	tenantID shared.ID,
	name string,
) (*Policy, error) {
	if tenantID.IsZero() {
		return nil, fmt.Errorf("%w: tenant id is required", shared.ErrValidation)
	}
	if name == "" {
		return nil, fmt.Errorf("%w: name is required", shared.ErrValidation)
	}

	now := time.Now().UTC()
	return &Policy{
		id:                  shared.NewID(),
		tenantID:            tenantID,
		name:                name,
		isDefault:           false,
		criticalDays:        DefaultSLADays["critical"],
		highDays:            DefaultSLADays["high"],
		mediumDays:          DefaultSLADays["medium"],
		lowDays:             DefaultSLADays["low"],
		infoDays:            DefaultSLADays["info"],
		warningThresholdPct: 80,
		escalationEnabled:   false,
		escalationConfig:    make(map[string]any),
		isActive:            true,
		createdAt:           now,
		updatedAt:           now,
	}, nil
}

// NewDefaultPolicy creates a new default SLA Policy for a tenant.
func NewDefaultPolicy(tenantID shared.ID) (*Policy, error) {
	policy, err := NewPolicy(tenantID, "Default SLA Policy")
	if err != nil {
		return nil, err
	}
	policy.isDefault = true
	policy.description = "Default SLA policy applied to all assets without a specific policy"
	return policy, nil
}

// Reconstitute recreates a Policy from persistence.
func Reconstitute(
	id shared.ID,
	tenantID shared.ID,
	assetID *shared.ID,
	name string,
	description string,
	isDefault bool,
	criticalDays int,
	highDays int,
	mediumDays int,
	lowDays int,
	infoDays int,
	warningThresholdPct int,
	escalationEnabled bool,
	escalationConfig map[string]any,
	isActive bool,
	createdAt time.Time,
	updatedAt time.Time,
) *Policy {
	if escalationConfig == nil {
		escalationConfig = make(map[string]any)
	}
	return &Policy{
		id:                  id,
		tenantID:            tenantID,
		assetID:             assetID,
		name:                name,
		description:         description,
		isDefault:           isDefault,
		criticalDays:        criticalDays,
		highDays:            highDays,
		mediumDays:          mediumDays,
		lowDays:             lowDays,
		infoDays:            infoDays,
		warningThresholdPct: warningThresholdPct,
		escalationEnabled:   escalationEnabled,
		escalationConfig:    escalationConfig,
		isActive:            isActive,
		createdAt:           createdAt,
		updatedAt:           updatedAt,
	}
}

// Getters

func (p *Policy) ID() shared.ID            { return p.id }
func (p *Policy) TenantID() shared.ID      { return p.tenantID }
func (p *Policy) AssetID() *shared.ID      { return p.assetID }
func (p *Policy) Name() string             { return p.name }
func (p *Policy) Description() string      { return p.description }
func (p *Policy) IsDefault() bool          { return p.isDefault }
func (p *Policy) CriticalDays() int        { return p.criticalDays }
func (p *Policy) HighDays() int            { return p.highDays }
func (p *Policy) MediumDays() int          { return p.mediumDays }
func (p *Policy) LowDays() int             { return p.lowDays }
func (p *Policy) InfoDays() int            { return p.infoDays }
func (p *Policy) WarningThresholdPct() int { return p.warningThresholdPct }
func (p *Policy) EscalationEnabled() bool  { return p.escalationEnabled }
func (p *Policy) IsActive() bool           { return p.isActive }
func (p *Policy) CreatedAt() time.Time     { return p.createdAt }
func (p *Policy) UpdatedAt() time.Time     { return p.updatedAt }

func (p *Policy) EscalationConfig() map[string]any {
	config := make(map[string]any, len(p.escalationConfig))
	for k, v := range p.escalationConfig {
		config[k] = v
	}
	return config
}

// GetDaysForSeverity returns the remediation days for a given severity.
func (p *Policy) GetDaysForSeverity(severity string) int {
	switch severity {
	case "critical":
		return p.criticalDays
	case "high":
		return p.highDays
	case "medium":
		return p.mediumDays
	case "low":
		return p.lowDays
	case "info", "none":
		return p.infoDays
	default:
		return p.infoDays
	}
}

// CalculateDeadline calculates the SLA deadline for a finding.
func (p *Policy) CalculateDeadline(severity string, detectedAt time.Time) time.Time {
	days := p.GetDaysForSeverity(severity)
	return detectedAt.Add(time.Duration(days) * 24 * time.Hour)
}

// Mutators

func (p *Policy) SetAssetID(assetID shared.ID) {
	p.assetID = &assetID
	p.updatedAt = time.Now().UTC()
}

func (p *Policy) UpdateName(name string) error {
	if name == "" {
		return fmt.Errorf("%w: name is required", shared.ErrValidation)
	}
	p.name = name
	p.updatedAt = time.Now().UTC()
	return nil
}

func (p *Policy) UpdateDescription(description string) {
	p.description = description
	p.updatedAt = time.Now().UTC()
}

func (p *Policy) SetDefault(isDefault bool) {
	p.isDefault = isDefault
	p.updatedAt = time.Now().UTC()
}

func (p *Policy) UpdateSLADays(critical, high, medium, low, info int) error {
	if critical < 1 || high < 1 || medium < 1 || low < 1 || info < 1 {
		return fmt.Errorf("%w: SLA days must be at least 1", shared.ErrValidation)
	}
	p.criticalDays = critical
	p.highDays = high
	p.mediumDays = medium
	p.lowDays = low
	p.infoDays = info
	p.updatedAt = time.Now().UTC()
	return nil
}

func (p *Policy) SetWarningThreshold(percent int) error {
	if percent < 1 || percent > 100 {
		return fmt.Errorf("%w: warning threshold must be between 1 and 100", shared.ErrValidation)
	}
	p.warningThresholdPct = percent
	p.updatedAt = time.Now().UTC()
	return nil
}

func (p *Policy) EnableEscalation(config map[string]any) {
	p.escalationEnabled = true
	if config != nil {
		p.escalationConfig = config
	}
	p.updatedAt = time.Now().UTC()
}

func (p *Policy) DisableEscalation() {
	p.escalationEnabled = false
	p.updatedAt = time.Now().UTC()
}

func (p *Policy) Activate() {
	p.isActive = true
	p.updatedAt = time.Now().UTC()
}

func (p *Policy) Deactivate() {
	p.isActive = false
	p.updatedAt = time.Now().UTC()
}

// IsAssetSpecific checks if this policy is for a specific asset.
func (p *Policy) IsAssetSpecific() bool {
	return p.assetID != nil && !p.assetID.IsZero()
}
