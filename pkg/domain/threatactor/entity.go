// Package threatactor provides domain models for threat actor intelligence.
// Threat actor data is enrichment — typically imported from STIX/TAXII feeds
// or MISP, not manually created. Links to CVEs and findings for prioritization.
package threatactor

import (
	"context"
	"fmt"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/pagination"
)

// ActorType classifies the threat actor.
type ActorType string

const (
	ActorTypeAPT         ActorType = "apt"
	ActorTypeCybercrime  ActorType = "cybercrime"
	ActorTypeHacktivist  ActorType = "hacktivist"
	ActorTypeInsider     ActorType = "insider"
	ActorTypeNationState ActorType = "nation_state"
	ActorTypeUnknown     ActorType = "unknown"
)

// ThreatActor represents a known threat actor profile.
type ThreatActor struct {
	id                 shared.ID
	tenantID           shared.ID
	name               string
	aliases            []string
	description        string
	actorType          ActorType
	sophistication     string
	motivation         string
	countryOfOrigin    string
	firstSeen          *time.Time
	lastSeen           *time.Time
	isActive           bool
	mitreGroupID       string
	ttps               []TTP
	targetIndustries   []string
	targetRegions      []string
	externalReferences []ExternalReference
	tags               []string
	createdAt          time.Time
	updatedAt          time.Time
}

// TTP represents a MITRE ATT&CK Tactic, Technique, and Procedure.
type TTP struct {
	Tactic        string `json:"tactic"`
	TechniqueID   string `json:"technique_id"`
	TechniqueName string `json:"technique_name"`
}

// ExternalReference links to external intelligence sources.
type ExternalReference struct {
	Source      string `json:"source"`
	URL         string `json:"url"`
	Description string `json:"description"`
}

// ThreatActorCVE links a threat actor to a CVE.
type ThreatActorCVE struct {
	id            shared.ID
	tenantID      shared.ID
	threatActorID shared.ID
	cveID         string
	confidence    string
	source        string
	firstObserved *time.Time
	notes         string
	createdAt     time.Time
}

// NewThreatActor creates a new threat actor.
func NewThreatActor(tenantID shared.ID, name string, actorType ActorType) (*ThreatActor, error) {
	if name == "" {
		return nil, fmt.Errorf("%w: name is required", shared.ErrValidation)
	}
	now := time.Now()
	return &ThreatActor{
		id:                 shared.NewID(),
		tenantID:           tenantID,
		name:               name,
		actorType:          actorType,
		isActive:           true,
		aliases:            []string{},
		ttps:               []TTP{},
		targetIndustries:   []string{},
		targetRegions:      []string{},
		externalReferences: []ExternalReference{},
		tags:               []string{},
		createdAt:          now,
		updatedAt:          now,
	}, nil
}

// ReconstituteThreatActor creates from persisted data.
func ReconstituteThreatActor(
	id, tenantID shared.ID,
	name string, aliases []string, description string,
	actorType ActorType, sophistication, motivation, countryOfOrigin string,
	firstSeen, lastSeen *time.Time, isActive bool,
	mitreGroupID string, ttps []TTP,
	targetIndustries, targetRegions []string,
	externalReferences []ExternalReference,
	tags []string,
	createdAt, updatedAt time.Time,
) *ThreatActor {
	return &ThreatActor{
		id: id, tenantID: tenantID,
		name: name, aliases: aliases, description: description,
		actorType: actorType, sophistication: sophistication,
		motivation: motivation, countryOfOrigin: countryOfOrigin,
		firstSeen: firstSeen, lastSeen: lastSeen, isActive: isActive,
		mitreGroupID: mitreGroupID, ttps: ttps,
		targetIndustries: targetIndustries, targetRegions: targetRegions,
		externalReferences: externalReferences,
		tags: tags,
		createdAt: createdAt, updatedAt: updatedAt,
	}
}

// Getters
func (t *ThreatActor) ID() shared.ID                        { return t.id }
func (t *ThreatActor) TenantID() shared.ID                   { return t.tenantID }
func (t *ThreatActor) Name() string                          { return t.name }
func (t *ThreatActor) Aliases() []string                      { return t.aliases }
func (t *ThreatActor) Description() string                    { return t.description }
func (t *ThreatActor) ActorType() ActorType                   { return t.actorType }
func (t *ThreatActor) Sophistication() string                 { return t.sophistication }
func (t *ThreatActor) Motivation() string                     { return t.motivation }
func (t *ThreatActor) CountryOfOrigin() string                { return t.countryOfOrigin }
func (t *ThreatActor) FirstSeen() *time.Time                  { return t.firstSeen }
func (t *ThreatActor) LastSeen() *time.Time                   { return t.lastSeen }
func (t *ThreatActor) IsActive() bool                         { return t.isActive }
func (t *ThreatActor) MitreGroupID() string                   { return t.mitreGroupID }
func (t *ThreatActor) TTPs() []TTP                            { return t.ttps }
func (t *ThreatActor) TargetIndustries() []string              { return t.targetIndustries }
func (t *ThreatActor) TargetRegions() []string                 { return t.targetRegions }
func (t *ThreatActor) ExternalReferences() []ExternalReference { return t.externalReferences }
func (t *ThreatActor) Tags() []string                          { return t.tags }
func (t *ThreatActor) CreatedAt() time.Time                    { return t.createdAt }
func (t *ThreatActor) UpdatedAt() time.Time                    { return t.updatedAt }

// Update sets mutable fields.
func (t *ThreatActor) Update(name, description string, actorType ActorType) {
	if name != "" {
		t.name = name
	}
	t.description = description
	t.actorType = actorType
	t.updatedAt = time.Now()
}

// SetIntel sets intelligence details.
func (t *ThreatActor) SetIntel(sophistication, motivation, country, mitreGroupID string) {
	t.sophistication = sophistication
	t.motivation = motivation
	t.countryOfOrigin = country
	t.mitreGroupID = mitreGroupID
	t.updatedAt = time.Now()
}

// SetTTPs sets MITRE ATT&CK tactics, techniques, and procedures.
func (t *ThreatActor) SetTTPs(ttps []TTP) {
	t.ttps = ttps
	t.updatedAt = time.Now()
}

// SetTargeting sets targeted industries and regions.
func (t *ThreatActor) SetTargeting(industries, regions []string) {
	t.targetIndustries = industries
	t.targetRegions = regions
	t.updatedAt = time.Now()
}

// Filter defines criteria for listing threat actors.
type Filter struct {
	TenantID  *shared.ID
	ActorType *ActorType
	IsActive  *bool
	Search    *string
}

// Repository defines persistence for threat actors.
type Repository interface {
	Create(ctx context.Context, actor *ThreatActor) error
	GetByID(ctx context.Context, tenantID, id shared.ID) (*ThreatActor, error)
	Update(ctx context.Context, actor *ThreatActor) error
	Delete(ctx context.Context, tenantID, id shared.ID) error
	List(ctx context.Context, filter Filter, page pagination.Pagination) (pagination.Result[*ThreatActor], error)
	// CVE links
	LinkCVE(ctx context.Context, cve *ThreatActorCVE) error
	ListCVEsByActor(ctx context.Context, tenantID, actorID shared.ID) ([]*ThreatActorCVE, error)
	ListActorsByCVE(ctx context.Context, tenantID shared.ID, cveID string) ([]*ThreatActor, error)
}
