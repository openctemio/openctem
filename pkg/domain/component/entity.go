package component

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
)

// Security limits
const (
	// MaxMetadataSize is the maximum allowed size for component metadata (64KB)
	MaxMetadataSize = 64 * 1024
	// MaxMetadataKeys is the maximum number of keys in metadata
	MaxMetadataKeys = 100
)

// Component represents a unique software package (Global).
type Component struct {
	id                 shared.ID
	name               string
	version            string
	ecosystem          Ecosystem
	purl               string
	license            string
	description        string
	homepage           string
	vulnerabilityCount int
	metadata           map[string]any
	createdAt          time.Time
	updatedAt          time.Time
}

// ComponentStats aggregates counts for dashboard.
type ComponentStats struct {
	TotalComponents        int `json:"total_components"`
	DirectDependencies     int `json:"direct_dependencies"`
	TransitiveDependencies int `json:"transitive_dependencies"`
	VulnerableComponents   int `json:"vulnerable_components"`

	// Extended stats from findings analysis
	TotalVulnerabilities int            `json:"total_vulnerabilities"`
	OutdatedComponents   int            `json:"outdated_components"`
	CisaKevComponents    int            `json:"cisa_kev_components"`
	VulnBySeverity       map[string]int `json:"vuln_by_severity"` // critical, high, medium, low
	LicenseRisks         map[string]int `json:"license_risks"`    // critical, high, medium, low
}

// EcosystemStats represents statistics for a single ecosystem.
type EcosystemStats struct {
	Ecosystem    string `json:"ecosystem"`
	Total        int    `json:"total"`
	Vulnerable   int    `json:"vulnerable"`
	Outdated     int    `json:"outdated"`
	ManifestFile string `json:"manifest_file"`
}

// VulnerableComponent represents a component with vulnerability details for display.
type VulnerableComponent struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem"`
	PURL      string `json:"purl"`
	License   string `json:"license,omitempty"`

	// Vulnerability breakdown
	CriticalCount int  `json:"critical_count"`
	HighCount     int  `json:"high_count"`
	MediumCount   int  `json:"medium_count"`
	LowCount      int  `json:"low_count"`
	TotalCount    int  `json:"total_count"`
	InCisaKev     bool `json:"in_cisa_kev"`
}

// LicenseStats represents statistics for a single license.
type LicenseStats struct {
	LicenseID string  `json:"license_id"`    // SPDX identifier
	Name      string  `json:"name"`          // Human-readable name
	Category  string  `json:"category"`      // permissive, copyleft, weak-copyleft, proprietary, public-domain, unknown
	Risk      string  `json:"risk"`          // critical, high, medium, low, none, unknown
	URL       *string `json:"url,omitempty"` // Link to license text (SPDX URL)
	Count     int     `json:"count"`         // Number of components using this license
}

// AssetDependency represents a component usage by an asset.
type AssetDependency struct {
	id                shared.ID
	tenantID          shared.ID
	assetID           shared.ID
	componentID       shared.ID
	path              string
	dependencyType    DependencyType
	manifestFile      string
	parentComponentID *shared.ID // For transitive deps: the parent that pulled this in
	depth             int        // Dependency depth: 1 = direct, 2+ = transitive (for risk scoring)
	component         *Component // For retrieval/joining
	createdAt         time.Time
	updatedAt         time.Time
}

// NewComponent creates a new Global Component.
func NewComponent(
	name string,
	version string,
	ecosystem Ecosystem,
) (*Component, error) {
	if name == "" {
		return nil, fmt.Errorf("%w: name is required", shared.ErrValidation)
	}
	if version == "" {
		return nil, fmt.Errorf("%w: version is required", shared.ErrValidation)
	}
	if !ecosystem.IsValid() {
		return nil, fmt.Errorf("%w: invalid ecosystem", shared.ErrValidation)
	}

	now := time.Now().UTC()
	c := &Component{
		id:                 shared.NewID(),
		name:               name,
		version:            version,
		ecosystem:          ecosystem,
		vulnerabilityCount: 0,
		metadata:           make(map[string]any),
		createdAt:          now,
		updatedAt:          now,
	}

	// Build PURL
	c.purl = BuildPURL(ecosystem, "", name, version)

	return c, nil
}

// NewAssetDependency creates a link between asset and component.
// Default depth is 1 (direct dependency). Use SetDepth() for transitive deps.
func NewAssetDependency(
	tenantID, assetID, componentID shared.ID,
	path string,
	depType DependencyType,
) (*AssetDependency, error) {
	if tenantID.IsZero() || assetID.IsZero() || componentID.IsZero() {
		return nil, fmt.Errorf("%w: missing required IDs", shared.ErrValidation)
	}

	now := time.Now().UTC()
	return &AssetDependency{
		id:             shared.NewID(),
		tenantID:       tenantID,
		assetID:        assetID,
		componentID:    componentID,
		path:           path,
		dependencyType: depType,
		depth:          1, // Default to direct dependency depth
		createdAt:      now,
		updatedAt:      now,
	}, nil
}

// Reconstitute recreates a Component from persistence.
func Reconstitute(
	id shared.ID,
	name string,
	version string,
	ecosystem Ecosystem,
	purl string,
	license string,
	description string,
	homepage string,
	vulnerabilityCount int,
	metadata map[string]any,
	createdAt time.Time,
	updatedAt time.Time,
) *Component {
	if metadata == nil {
		metadata = make(map[string]any)
	}
	return &Component{
		id:                 id,
		name:               name,
		version:            version,
		ecosystem:          ecosystem,
		purl:               purl,
		license:            license,
		description:        description,
		homepage:           homepage,
		vulnerabilityCount: vulnerabilityCount,
		metadata:           metadata,
		createdAt:          createdAt,
		updatedAt:          updatedAt,
	}
}

// ReconstituteAssetDependency recreates a dependency link.
func ReconstituteAssetDependency(
	id, tenantID, assetID, componentID shared.ID,
	path string,
	depType DependencyType,
	manifestFile string,
	parentComponentID *shared.ID,
	depth int,
	createdAt, updatedAt time.Time,
) *AssetDependency {
	// Default depth to 1 if not set
	if depth < 1 {
		depth = 1
	}
	return &AssetDependency{
		id:                id,
		tenantID:          tenantID,
		assetID:           assetID,
		componentID:       componentID,
		path:              path,
		dependencyType:    depType,
		manifestFile:      manifestFile,
		parentComponentID: parentComponentID,
		depth:             depth,
		createdAt:         createdAt,
		updatedAt:         updatedAt,
	}
}

// ID returns the component ID.
func (c *Component) ID() shared.ID { return c.id }

// Name returns the component name.
func (c *Component) Name() string { return c.name }

// Version returns the version.
func (c *Component) Version() string { return c.version }

// Ecosystem returns the ecosystem.
func (c *Component) Ecosystem() Ecosystem { return c.ecosystem }

// PURL returns the Package URL.
func (c *Component) PURL() string { return c.purl }

// License returns the license.
func (c *Component) License() string { return c.license }

// Description returns the description.
func (c *Component) Description() string { return c.description }

// Homepage returns the homepage.
func (c *Component) Homepage() string { return c.homepage }

// VulnerabilityCount returns the vulnerability count.
func (c *Component) VulnerabilityCount() int { return c.vulnerabilityCount }

// Metadata returns a copy of the metadata.
func (c *Component) Metadata() map[string]any {
	metadata := make(map[string]any, len(c.metadata))
	for k, v := range c.metadata {
		metadata[k] = v
	}
	return metadata
}

// CreatedAt returns the creation time.
func (c *Component) CreatedAt() time.Time { return c.createdAt }

// UpdatedAt returns the last update time.
func (c *Component) UpdatedAt() time.Time { return c.updatedAt }

// Mutators

func (c *Component) UpdateLicense(license string) {
	c.license = license
	c.updatedAt = time.Now().UTC()
}

func (c *Component) UpdateDescription(desc string) {
	c.description = desc
	c.updatedAt = time.Now().UTC()
}

func (c *Component) UpdateHomepage(url string) {
	c.homepage = url
	c.updatedAt = time.Now().UTC()
}

// SetPURL overrides the generated PURL with a custom one.
// Use this when the agent provides a more accurate PURL.
func (c *Component) SetPURL(purl string) {
	if purl != "" {
		c.purl = purl
		c.updatedAt = time.Now().UTC()
	}
}

// SetMetadata sets a metadata key-value pair with size validation.
// Returns error if metadata exceeds size limits (DoS prevention).
func (c *Component) SetMetadata(key string, value any) error {
	// Check key count limit
	if _, exists := c.metadata[key]; !exists && len(c.metadata) >= MaxMetadataKeys {
		return fmt.Errorf("%w: metadata key limit exceeded (%d)", shared.ErrValidation, MaxMetadataKeys)
	}

	// Temporarily add the key to check size
	c.metadata[key] = value

	// Check serialized size
	data, err := json.Marshal(c.metadata)
	if err != nil {
		delete(c.metadata, key)
		return fmt.Errorf("%w: invalid metadata value", shared.ErrValidation)
	}

	if len(data) > MaxMetadataSize {
		delete(c.metadata, key)
		return fmt.Errorf("%w: metadata size exceeds limit (%d bytes)", shared.ErrValidation, MaxMetadataSize)
	}

	c.updatedAt = time.Now().UTC()
	return nil
}

// AssetDependency Methods

func (ad *AssetDependency) ID() shared.ID                  { return ad.id }
func (ad *AssetDependency) TenantID() shared.ID            { return ad.tenantID }
func (ad *AssetDependency) AssetID() shared.ID             { return ad.assetID }
func (ad *AssetDependency) ComponentID() shared.ID         { return ad.componentID }
func (ad *AssetDependency) Path() string                   { return ad.path }
func (ad *AssetDependency) DependencyType() DependencyType { return ad.dependencyType }
func (ad *AssetDependency) Component() *Component          { return ad.component }

func (ad *AssetDependency) SetComponent(c *Component) {
	ad.component = c
}

func (ad *AssetDependency) ManifestFile() string          { return ad.manifestFile }
func (ad *AssetDependency) ParentComponentID() *shared.ID { return ad.parentComponentID }
func (ad *AssetDependency) Depth() int                    { return ad.depth }
func (ad *AssetDependency) CreatedAt() time.Time          { return ad.createdAt }
func (ad *AssetDependency) UpdatedAt() time.Time          { return ad.updatedAt }

// SetParentComponentID sets the parent dependency ID for transitive deps.
// Returns error if attempting to create a circular dependency (self-reference).
func (ad *AssetDependency) SetParentComponentID(parentID *shared.ID) error {
	// Prevent self-referencing (circular dependency check)
	if parentID != nil && *parentID == ad.id {
		return fmt.Errorf("%w: circular dependency detected (self-reference)", shared.ErrValidation)
	}
	ad.parentComponentID = parentID
	return nil
}

// SetDepth sets the dependency depth for risk scoring.
func (ad *AssetDependency) SetDepth(depth int) {
	if depth < 1 {
		depth = 1
	}
	ad.depth = depth
}
