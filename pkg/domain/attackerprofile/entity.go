package attackerprofile

import (
	"fmt"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
)

// ProfileType represents the category of attacker profile.
type ProfileType string

const (
	ProfileExternalUnauth      ProfileType = "external_unauth"
	ProfileExternalStolenCreds ProfileType = "external_stolen_creds"
	ProfileMaliciousInsider    ProfileType = "malicious_insider"
	ProfileSupplierCompromise  ProfileType = "supplier_compromise"
	ProfileCustom              ProfileType = "custom"
)

// Capabilities describes what the attacker can do.
type Capabilities struct {
	NetworkAccess   string   `json:"network_access"`   // external, internal, physical
	CredentialLevel string   `json:"credential_level"` // none, user, admin
	Persistence     bool     `json:"persistence"`
	Tools           []string `json:"tools"` // commodity, custom, zero-day, osint, etc.
}

// AttackerProfile represents a threat model assumption for a CTEM cycle.
type AttackerProfile struct {
	id           shared.ID
	tenantID     shared.ID
	name         string
	profileType  ProfileType
	description  string
	capabilities Capabilities
	assumptions  string
	isDefault    bool
	createdBy    *shared.ID
	createdAt    time.Time
	updatedAt    time.Time
}

// AttackerProfileData is the persistence representation.
type AttackerProfileData struct {
	ID           shared.ID
	TenantID     shared.ID
	Name         string
	ProfileType  ProfileType
	Description  string
	Capabilities Capabilities
	Assumptions  string
	IsDefault    bool
	CreatedBy    *shared.ID
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// NewAttackerProfile creates a new attacker profile.
func NewAttackerProfile(
	tenantID shared.ID,
	name string,
	profileType ProfileType,
	createdBy shared.ID,
) (*AttackerProfile, error) {
	if name == "" {
		return nil, fmt.Errorf("%w: name is required", shared.ErrValidation)
	}

	now := time.Now()
	return &AttackerProfile{
		id:          shared.NewID(),
		tenantID:    tenantID,
		name:        name,
		profileType: profileType,
		createdBy:   &createdBy,
		createdAt:   now,
		updatedAt:   now,
	}, nil
}

// ReconstituteAttackerProfile recreates from persistence.
func ReconstituteAttackerProfile(data AttackerProfileData) *AttackerProfile {
	return &AttackerProfile{
		id:           data.ID,
		tenantID:     data.TenantID,
		name:         data.Name,
		profileType:  data.ProfileType,
		description:  data.Description,
		capabilities: data.Capabilities,
		assumptions:  data.Assumptions,
		isDefault:    data.IsDefault,
		createdBy:    data.CreatedBy,
		createdAt:    data.CreatedAt,
		updatedAt:    data.UpdatedAt,
	}
}

// Getters
func (p *AttackerProfile) ID() shared.ID           { return p.id }
func (p *AttackerProfile) TenantID() shared.ID     { return p.tenantID }
func (p *AttackerProfile) Name() string             { return p.name }
func (p *AttackerProfile) ProfileType() ProfileType { return p.profileType }
func (p *AttackerProfile) Description() string      { return p.description }
func (p *AttackerProfile) Capabilities() Capabilities { return p.capabilities }
func (p *AttackerProfile) Assumptions() string      { return p.assumptions }
func (p *AttackerProfile) IsDefault() bool          { return p.isDefault }
func (p *AttackerProfile) CreatedAt() time.Time     { return p.createdAt }

// SetDescription updates the description.
func (p *AttackerProfile) SetDescription(desc string) {
	p.description = desc
	p.updatedAt = time.Now()
}

// SetCapabilities updates the capabilities.
func (p *AttackerProfile) SetCapabilities(caps Capabilities) {
	p.capabilities = caps
	p.updatedAt = time.Now()
}

// SetAssumptions updates the assumptions text.
func (p *AttackerProfile) SetAssumptions(assumptions string) {
	p.assumptions = assumptions
	p.updatedAt = time.Now()
}
