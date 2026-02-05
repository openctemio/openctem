// Package asset_group provides domain models for asset group management.
// Asset groups organize assets for CTEM (Continuous Threat Exposure Management) scoping.
package assetgroup

import (
	"fmt"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
)

// AssetGroup represents a logical grouping of assets.
type AssetGroup struct {
	id           shared.ID
	tenantID     shared.ID
	name         string
	description  string
	environment  Environment
	criticality  Criticality
	businessUnit string
	owner        string
	ownerEmail   string
	tags         []string

	// Computed counts
	assetCount      int
	domainCount     int
	websiteCount    int
	serviceCount    int
	repositoryCount int
	cloudCount      int
	credentialCount int

	// Risk metrics
	riskScore    int
	findingCount int

	createdAt time.Time
	updatedAt time.Time
}

// NewAssetGroup creates a new AssetGroup entity.
func NewAssetGroup(name string, environment Environment, criticality Criticality) (*AssetGroup, error) {
	if name == "" {
		return nil, fmt.Errorf("%w: name is required", shared.ErrValidation)
	}
	if !environment.IsValid() {
		return nil, fmt.Errorf("%w: invalid environment", shared.ErrValidation)
	}
	if !criticality.IsValid() {
		return nil, fmt.Errorf("%w: invalid criticality", shared.ErrValidation)
	}

	now := time.Now().UTC()
	return &AssetGroup{
		id:          shared.NewID(),
		name:        name,
		environment: environment,
		criticality: criticality,
		tags:        make([]string, 0),
		createdAt:   now,
		updatedAt:   now,
	}, nil
}

// NewAssetGroupWithTenant creates a new AssetGroup entity with tenant.
func NewAssetGroupWithTenant(tenantID shared.ID, name string, environment Environment, criticality Criticality) (*AssetGroup, error) {
	g, err := NewAssetGroup(name, environment, criticality)
	if err != nil {
		return nil, err
	}
	g.tenantID = tenantID
	return g, nil
}

// Reconstitute recreates an AssetGroup from persistence.
func Reconstitute(
	id shared.ID,
	tenantID shared.ID,
	name string,
	description string,
	environment Environment,
	criticality Criticality,
	businessUnit string,
	owner string,
	ownerEmail string,
	tags []string,
	assetCount int,
	domainCount int,
	websiteCount int,
	serviceCount int,
	repositoryCount int,
	cloudCount int,
	credentialCount int,
	riskScore int,
	findingCount int,
	createdAt time.Time,
	updatedAt time.Time,
) *AssetGroup {
	if tags == nil {
		tags = make([]string, 0)
	}
	return &AssetGroup{
		id:              id,
		tenantID:        tenantID,
		name:            name,
		description:     description,
		environment:     environment,
		criticality:     criticality,
		businessUnit:    businessUnit,
		owner:           owner,
		ownerEmail:      ownerEmail,
		tags:            tags,
		assetCount:      assetCount,
		domainCount:     domainCount,
		websiteCount:    websiteCount,
		serviceCount:    serviceCount,
		repositoryCount: repositoryCount,
		cloudCount:      cloudCount,
		credentialCount: credentialCount,
		riskScore:       riskScore,
		findingCount:    findingCount,
		createdAt:       createdAt,
		updatedAt:       updatedAt,
	}
}

// Getters

func (g *AssetGroup) ID() shared.ID            { return g.id }
func (g *AssetGroup) TenantID() shared.ID      { return g.tenantID }
func (g *AssetGroup) Name() string             { return g.name }
func (g *AssetGroup) Description() string      { return g.description }
func (g *AssetGroup) Environment() Environment { return g.environment }
func (g *AssetGroup) Criticality() Criticality { return g.criticality }
func (g *AssetGroup) BusinessUnit() string     { return g.businessUnit }
func (g *AssetGroup) Owner() string            { return g.owner }
func (g *AssetGroup) OwnerEmail() string       { return g.ownerEmail }
func (g *AssetGroup) AssetCount() int          { return g.assetCount }
func (g *AssetGroup) DomainCount() int         { return g.domainCount }
func (g *AssetGroup) WebsiteCount() int        { return g.websiteCount }
func (g *AssetGroup) ServiceCount() int        { return g.serviceCount }
func (g *AssetGroup) RepositoryCount() int     { return g.repositoryCount }
func (g *AssetGroup) CloudCount() int          { return g.cloudCount }
func (g *AssetGroup) CredentialCount() int     { return g.credentialCount }
func (g *AssetGroup) RiskScore() int           { return g.riskScore }
func (g *AssetGroup) FindingCount() int        { return g.findingCount }
func (g *AssetGroup) CreatedAt() time.Time     { return g.createdAt }
func (g *AssetGroup) UpdatedAt() time.Time     { return g.updatedAt }

func (g *AssetGroup) Tags() []string {
	result := make([]string, len(g.tags))
	copy(result, g.tags)
	return result
}

// Setters

func (g *AssetGroup) SetTenantID(tenantID shared.ID) {
	g.tenantID = tenantID
}

func (g *AssetGroup) UpdateName(name string) error {
	if name == "" {
		return fmt.Errorf("%w: name is required", shared.ErrValidation)
	}
	g.name = name
	g.updatedAt = time.Now().UTC()
	return nil
}

func (g *AssetGroup) UpdateDescription(description string) {
	g.description = description
	g.updatedAt = time.Now().UTC()
}

func (g *AssetGroup) UpdateEnvironment(env Environment) error {
	if !env.IsValid() {
		return fmt.Errorf("%w: invalid environment", shared.ErrValidation)
	}
	g.environment = env
	g.updatedAt = time.Now().UTC()
	return nil
}

func (g *AssetGroup) UpdateCriticality(crit Criticality) error {
	if !crit.IsValid() {
		return fmt.Errorf("%w: invalid criticality", shared.ErrValidation)
	}
	g.criticality = crit
	g.updatedAt = time.Now().UTC()
	return nil
}

func (g *AssetGroup) UpdateBusinessUnit(bu string) {
	g.businessUnit = bu
	g.updatedAt = time.Now().UTC()
}

func (g *AssetGroup) UpdateOwner(owner, email string) {
	g.owner = owner
	g.ownerEmail = email
	g.updatedAt = time.Now().UTC()
}

func (g *AssetGroup) SetTags(tags []string) {
	if tags == nil {
		tags = make([]string, 0)
	}
	g.tags = tags
	g.updatedAt = time.Now().UTC()
}

func (g *AssetGroup) AddTag(tag string) {
	if tag == "" {
		return
	}
	for _, t := range g.tags {
		if t == tag {
			return
		}
	}
	g.tags = append(g.tags, tag)
	g.updatedAt = time.Now().UTC()
}

func (g *AssetGroup) RemoveTag(tag string) {
	for i, t := range g.tags {
		if t == tag {
			g.tags = append(g.tags[:i], g.tags[i+1:]...)
			g.updatedAt = time.Now().UTC()
			return
		}
	}
}

// UpdateCounts updates the asset counts.
func (g *AssetGroup) UpdateCounts(total, domain, website, service, repository, cloud, credential int) {
	g.assetCount = total
	g.domainCount = domain
	g.websiteCount = website
	g.serviceCount = service
	g.repositoryCount = repository
	g.cloudCount = cloud
	g.credentialCount = credential
	g.updatedAt = time.Now().UTC()
}

// UpdateRiskMetrics updates risk score and finding count.
func (g *AssetGroup) UpdateRiskMetrics(riskScore, findingCount int) {
	if riskScore < 0 {
		riskScore = 0
	}
	if riskScore > 100 {
		riskScore = 100
	}
	if findingCount < 0 {
		findingCount = 0
	}
	g.riskScore = riskScore
	g.findingCount = findingCount
	g.updatedAt = time.Now().UTC()
}
