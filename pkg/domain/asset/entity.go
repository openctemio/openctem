package asset

import (
	"fmt"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
)

// Asset represents an asset entity in the domain.
type Asset struct {
	id           shared.ID
	tenantID     shared.ID
	parentID     *shared.ID // For hierarchical assets (e.g., subdomain -> domain)
	ownerID      *shared.ID // User who owns this asset
	name         string
	assetType    AssetType
	criticality  Criticality
	status       Status
	scope        Scope
	exposure     Exposure
	riskScore    int
	findingCount int
	description  string
	tags         []string
	metadata     map[string]any
	properties   map[string]any // Type-specific properties (JSONB)

	// External provider info
	provider       Provider
	externalID     string // ID in external system
	classification string

	// Sync status
	syncStatus   SyncStatus
	lastSyncedAt *time.Time
	syncError    string

	// Discovery tracking (for recon-discovered assets)
	discoverySource string     // How discovered: agent, integration, manual, import
	discoveryTool   string     // Tool that discovered: subfinder, dnsx, naabu, httpx, katana
	discoveredAt    *time.Time // When first discovered by recon tools

	// CTEM: Compliance Context
	complianceScope    []string           // Compliance frameworks: PCI-DSS, HIPAA, SOC2, GDPR, ISO27001
	dataClassification DataClassification // public, internal, confidential, restricted, secret
	piiDataExposed     bool               // Contains Personally Identifiable Information
	phiDataExposed     bool               // Contains Protected Health Information
	regulatoryOwnerID  *shared.ID         // Compliance officer responsible

	// CTEM: Enhanced Exposure Tracking
	isInternetAccessible bool       // Directly reachable from internet
	exposureChangedAt    *time.Time // When exposure level last changed
	lastExposureLevel    Exposure   // Previous exposure for tracking changes

	firstSeen time.Time
	lastSeen  time.Time
	createdAt time.Time
	updatedAt time.Time
}

// NewAsset creates a new Asset entity.
func NewAsset(name string, assetType AssetType, criticality Criticality) (*Asset, error) {
	if name == "" {
		return nil, fmt.Errorf("%w: name is required", shared.ErrValidation)
	}
	if !assetType.IsValid() {
		return nil, fmt.Errorf("%w: invalid asset type", shared.ErrValidation)
	}
	if !criticality.IsValid() {
		return nil, fmt.Errorf("%w: invalid criticality", shared.ErrValidation)
	}

	now := time.Now().UTC()
	return &Asset{
		id:           shared.NewID(),
		name:         name,
		assetType:    assetType,
		criticality:  criticality,
		status:       StatusActive,
		scope:        ScopeInternal,
		exposure:     ExposureUnknown,
		riskScore:    0,
		findingCount: 0,
		tags:         make([]string, 0),
		metadata:     make(map[string]any),
		properties:   make(map[string]any),
		syncStatus:   SyncStatusSynced,
		firstSeen:    now,
		lastSeen:     now,
		createdAt:    now,
		updatedAt:    now,
	}, nil
}

// NewAssetWithTenant creates a new Asset entity with tenant.
func NewAssetWithTenant(tenantID shared.ID, name string, assetType AssetType, criticality Criticality) (*Asset, error) {
	a, err := NewAsset(name, assetType, criticality)
	if err != nil {
		return nil, err
	}
	a.tenantID = tenantID
	return a, nil
}

// Reconstitute recreates an Asset from persistence (used by repository).
func Reconstitute(
	assetID shared.ID,
	tenantID shared.ID,
	parentID *shared.ID,
	ownerID *shared.ID,
	name string,
	assetType AssetType,
	criticality Criticality,
	status Status,
	scope Scope,
	exposure Exposure,
	riskScore int,
	findingCount int,
	description string,
	tags []string,
	metadata map[string]any,
	properties map[string]any,
	provider Provider,
	externalID string,
	classification string,
	syncStatus SyncStatus,
	lastSyncedAt *time.Time,
	syncError string,
	discoverySource string,
	discoveryTool string,
	discoveredAt *time.Time,
	// CTEM fields
	complianceScope []string,
	dataClassification DataClassification,
	piiDataExposed bool,
	phiDataExposed bool,
	regulatoryOwnerID *shared.ID,
	isInternetAccessible bool,
	exposureChangedAt *time.Time,
	lastExposureLevel Exposure,
	// Timestamps
	firstSeen, lastSeen time.Time,
	createdAt, updatedAt time.Time,
) *Asset {
	if tags == nil {
		tags = make([]string, 0)
	}
	if metadata == nil {
		metadata = make(map[string]any)
	}
	if properties == nil {
		properties = make(map[string]any)
	}
	if complianceScope == nil {
		complianceScope = make([]string, 0)
	}
	return &Asset{
		id:              assetID,
		tenantID:        tenantID,
		parentID:        parentID,
		ownerID:         ownerID,
		name:            name,
		assetType:       assetType,
		criticality:     criticality,
		status:          status,
		scope:           scope,
		exposure:        exposure,
		riskScore:       riskScore,
		findingCount:    findingCount,
		description:     description,
		tags:            tags,
		metadata:        metadata,
		properties:      properties,
		provider:        provider,
		externalID:      externalID,
		classification:  classification,
		syncStatus:      syncStatus,
		lastSyncedAt:    lastSyncedAt,
		syncError:       syncError,
		discoverySource: discoverySource,
		discoveryTool:   discoveryTool,
		discoveredAt:    discoveredAt,
		// CTEM fields
		complianceScope:      complianceScope,
		dataClassification:   dataClassification,
		piiDataExposed:       piiDataExposed,
		phiDataExposed:       phiDataExposed,
		regulatoryOwnerID:    regulatoryOwnerID,
		isInternetAccessible: isInternetAccessible,
		exposureChangedAt:    exposureChangedAt,
		lastExposureLevel:    lastExposureLevel,
		// Timestamps
		firstSeen: firstSeen,
		lastSeen:  lastSeen,
		createdAt: createdAt,
		updatedAt: updatedAt,
	}
}

// ID returns the asset ID.
func (a *Asset) ID() shared.ID {
	return a.id
}

// TenantID returns the tenant ID.
func (a *Asset) TenantID() shared.ID {
	return a.tenantID
}

// Name returns the asset name.
func (a *Asset) Name() string {
	return a.name
}

// Type returns the asset type.
func (a *Asset) Type() AssetType {
	return a.assetType
}

// Criticality returns the asset criticality.
func (a *Asset) Criticality() Criticality {
	return a.criticality
}

// Status returns the asset status.
func (a *Asset) Status() Status {
	return a.status
}

// Scope returns the asset scope.
func (a *Asset) Scope() Scope {
	return a.scope
}

// Exposure returns the asset exposure level.
func (a *Asset) Exposure() Exposure {
	return a.exposure
}

// RiskScore returns the asset risk score.
func (a *Asset) RiskScore() int {
	return a.riskScore
}

// FindingCount returns the number of findings for this asset.
func (a *Asset) FindingCount() int {
	return a.findingCount
}

// Description returns the asset description.
func (a *Asset) Description() string {
	return a.description
}

// FirstSeen returns when the asset was first discovered.
func (a *Asset) FirstSeen() time.Time {
	return a.firstSeen
}

// LastSeen returns when the asset was last seen.
func (a *Asset) LastSeen() time.Time {
	return a.lastSeen
}

// Tags returns the asset tags.
func (a *Asset) Tags() []string {
	result := make([]string, len(a.tags))
	copy(result, a.tags)
	return result
}

// Metadata returns the asset metadata.
func (a *Asset) Metadata() map[string]any {
	result := make(map[string]any, len(a.metadata))
	for k, v := range a.metadata {
		result[k] = v
	}
	return result
}

// CreatedAt returns the creation timestamp.
func (a *Asset) CreatedAt() time.Time {
	return a.createdAt
}

// UpdatedAt returns the last update timestamp.
func (a *Asset) UpdatedAt() time.Time {
	return a.updatedAt
}

// UpdateName updates the asset name.
func (a *Asset) UpdateName(name string) error {
	if name == "" {
		return fmt.Errorf("%w: name is required", shared.ErrValidation)
	}
	a.name = name
	a.updatedAt = time.Now().UTC()
	return nil
}

// UpdateCriticality updates the asset criticality.
func (a *Asset) UpdateCriticality(criticality Criticality) error {
	if !criticality.IsValid() {
		return fmt.Errorf("%w: invalid criticality", shared.ErrValidation)
	}
	a.criticality = criticality
	a.updatedAt = time.Now().UTC()
	return nil
}

// UpdateDescription updates the asset description.
func (a *Asset) UpdateDescription(description string) {
	a.description = description
	a.updatedAt = time.Now().UTC()
}

// UpdateScope updates the asset scope.
func (a *Asset) UpdateScope(scope Scope) error {
	if !scope.IsValid() {
		return fmt.Errorf("%w: invalid scope", shared.ErrValidation)
	}
	a.scope = scope
	a.updatedAt = time.Now().UTC()
	return nil
}

// UpdateExposure updates the asset exposure level.
func (a *Asset) UpdateExposure(exposure Exposure) error {
	if !exposure.IsValid() {
		return fmt.Errorf("%w: invalid exposure", shared.ErrValidation)
	}
	a.exposure = exposure
	a.updatedAt = time.Now().UTC()
	return nil
}

// UpdateRiskScore updates the asset risk score.
func (a *Asset) UpdateRiskScore(score int) error {
	if score < 0 || score > 100 {
		return fmt.Errorf("%w: risk score must be between 0 and 100", shared.ErrValidation)
	}
	a.riskScore = score
	a.updatedAt = time.Now().UTC()
	return nil
}

// UpdateFindingCount updates the finding count.
func (a *Asset) UpdateFindingCount(count int) {
	if count < 0 {
		count = 0
	}
	a.findingCount = count
	a.updatedAt = time.Now().UTC()
}

// IncrementFindingCount increments the finding count by 1.
func (a *Asset) IncrementFindingCount() {
	a.findingCount++
	a.updatedAt = time.Now().UTC()
}

// DecrementFindingCount decrements the finding count by 1.
func (a *Asset) DecrementFindingCount() {
	if a.findingCount > 0 {
		a.findingCount--
		a.updatedAt = time.Now().UTC()
	}
}

// MarkSeen updates the last seen timestamp.
func (a *Asset) MarkSeen() {
	a.lastSeen = time.Now().UTC()
	a.updatedAt = time.Now().UTC()
}

// SetTenantID sets the tenant ID.
func (a *Asset) SetTenantID(tenantID shared.ID) {
	a.tenantID = tenantID
}

// CalculateRiskScore calculates and updates the risk score based on exposure, criticality, and findings.
func (a *Asset) CalculateRiskScore() {
	baseScore := a.exposure.BaseRiskScore()
	criticalityScore := a.criticality.Score() / 4 // Max 25 points from criticality

	// Add finding impact (simplified - could be enhanced with finding severity)
	findingImpact := 0
	if a.findingCount > 0 {
		findingImpact = min(a.findingCount*5, 35) // Max 35 points from findings
	}

	rawScore := baseScore + criticalityScore + findingImpact
	multiplier := a.exposure.ExposureMultiplier()

	finalScore := int(float64(rawScore) * multiplier)
	if finalScore > 100 {
		finalScore = 100
	}
	if finalScore < 0 {
		finalScore = 0
	}

	a.riskScore = finalScore
	a.updatedAt = time.Now().UTC()
}

// AddTag adds a tag to the asset.
func (a *Asset) AddTag(tag string) {
	if tag == "" {
		return
	}
	for _, t := range a.tags {
		if t == tag {
			return
		}
	}
	a.tags = append(a.tags, tag)
	a.updatedAt = time.Now().UTC()
}

// RemoveTag removes a tag from the asset.
func (a *Asset) RemoveTag(tag string) {
	for i, t := range a.tags {
		if t == tag {
			a.tags = append(a.tags[:i], a.tags[i+1:]...)
			a.updatedAt = time.Now().UTC()
			return
		}
	}
}

// SetMetadata sets a metadata key-value pair.
func (a *Asset) SetMetadata(key string, value any) {
	if key == "" {
		return
	}
	a.metadata[key] = value
	a.updatedAt = time.Now().UTC()
}

// Activate activates the asset.
func (a *Asset) Activate() {
	a.status = StatusActive
	a.updatedAt = time.Now().UTC()
}

// Deactivate deactivates the asset.
func (a *Asset) Deactivate() {
	a.status = StatusInactive
	a.updatedAt = time.Now().UTC()
}

// Archive archives the asset.
func (a *Asset) Archive() {
	a.status = StatusArchived
	a.updatedAt = time.Now().UTC()
}

// IsActive returns true if the asset is active.
func (a *Asset) IsActive() bool {
	return a.status == StatusActive
}

// IsCritical returns true if the asset is critical.
func (a *Asset) IsCritical() bool {
	return a.criticality == CriticalityCritical
}

// IsRepository returns true if the asset is a repository type.
func (a *Asset) IsRepository() bool {
	return a.assetType.IsRepository()
}

// ParentID returns the parent asset ID.
func (a *Asset) ParentID() *shared.ID {
	return a.parentID
}

// OwnerID returns the owner user ID.
func (a *Asset) OwnerID() *shared.ID {
	return a.ownerID
}

// Provider returns the external provider.
func (a *Asset) Provider() Provider {
	return a.provider
}

// ExternalID returns the external system ID.
func (a *Asset) ExternalID() string {
	return a.externalID
}

// Classification returns the asset classification.
func (a *Asset) Classification() string {
	return a.classification
}

// SyncStatus returns the sync status.
func (a *Asset) SyncStatus() SyncStatus {
	return a.syncStatus
}

// LastSyncedAt returns the last sync timestamp.
func (a *Asset) LastSyncedAt() *time.Time {
	return a.lastSyncedAt
}

// SyncError returns the last sync error.
func (a *Asset) SyncError() string {
	return a.syncError
}

// Properties returns a copy of the type-specific properties.
func (a *Asset) Properties() map[string]any {
	result := make(map[string]any, len(a.properties))
	for k, v := range a.properties {
		result[k] = v
	}
	return result
}

// SetParentID sets the parent asset ID.
func (a *Asset) SetParentID(parentID *shared.ID) {
	a.parentID = parentID
	a.updatedAt = time.Now().UTC()
}

// SetOwnerID sets the owner user ID.
func (a *Asset) SetOwnerID(ownerID *shared.ID) {
	a.ownerID = ownerID
	a.updatedAt = time.Now().UTC()
}

// SetProvider sets the external provider.
func (a *Asset) SetProvider(provider Provider) {
	a.provider = provider
	a.updatedAt = time.Now().UTC()
}

// SetExternalID sets the external system ID.
func (a *Asset) SetExternalID(externalID string) {
	a.externalID = externalID
	a.updatedAt = time.Now().UTC()
}

// SetClassification sets the asset classification.
func (a *Asset) SetClassification(classification string) {
	a.classification = classification
	a.updatedAt = time.Now().UTC()
}

// SetProperty sets a type-specific property.
func (a *Asset) SetProperty(key string, value any) {
	if key == "" {
		return
	}
	a.properties[key] = value
	a.updatedAt = time.Now().UTC()
}

// GetProperty gets a type-specific property.
func (a *Asset) GetProperty(key string) (any, bool) {
	v, ok := a.properties[key]
	return v, ok
}

// SetProperties replaces all properties.
func (a *Asset) SetProperties(properties map[string]any) {
	if properties == nil {
		properties = make(map[string]any)
	}
	a.properties = properties
	a.updatedAt = time.Now().UTC()
}

// MarkSyncing marks the asset as syncing.
func (a *Asset) MarkSyncing() {
	a.syncStatus = SyncStatusSyncing
	a.updatedAt = time.Now().UTC()
}

// MarkSynced marks the asset as synced.
func (a *Asset) MarkSynced() {
	a.syncStatus = SyncStatusSynced
	now := time.Now().UTC()
	a.lastSyncedAt = &now
	a.syncError = ""
	a.updatedAt = now
}

// MarkSyncError marks the asset with a sync error.
func (a *Asset) MarkSyncError(err string) {
	a.syncStatus = SyncStatusError
	a.syncError = err
	a.updatedAt = time.Now().UTC()
}

// DisableSync disables syncing for this asset.
func (a *Asset) DisableSync() {
	a.syncStatus = SyncStatusDisabled
	a.updatedAt = time.Now().UTC()
}

// EnableSync enables syncing for this asset.
func (a *Asset) EnableSync() {
	a.syncStatus = SyncStatusPending
	a.updatedAt = time.Now().UTC()
}

// DiscoverySource returns the discovery source.
func (a *Asset) DiscoverySource() string {
	return a.discoverySource
}

// DiscoveryTool returns the discovery tool.
func (a *Asset) DiscoveryTool() string {
	return a.discoveryTool
}

// DiscoveredAt returns when the asset was discovered.
func (a *Asset) DiscoveredAt() *time.Time {
	return a.discoveredAt
}

// SetDiscoverySource sets the discovery source.
func (a *Asset) SetDiscoverySource(source string) {
	a.discoverySource = source
	a.updatedAt = time.Now().UTC()
}

// SetDiscoveryTool sets the discovery tool.
func (a *Asset) SetDiscoveryTool(tool string) {
	a.discoveryTool = tool
	a.updatedAt = time.Now().UTC()
}

// SetDiscoveredAt sets when the asset was discovered.
func (a *Asset) SetDiscoveredAt(t *time.Time) {
	a.discoveredAt = t
	a.updatedAt = time.Now().UTC()
}

// SetDiscoveryInfo sets all discovery-related fields at once.
func (a *Asset) SetDiscoveryInfo(source, tool string, discoveredAt *time.Time) {
	a.discoverySource = source
	a.discoveryTool = tool
	a.discoveredAt = discoveredAt
	a.updatedAt = time.Now().UTC()
}

// =============================================================================
// CTEM: Compliance Context Methods
// =============================================================================

// ComplianceScope returns the compliance frameworks this asset is in scope for.
func (a *Asset) ComplianceScope() []string {
	result := make([]string, len(a.complianceScope))
	copy(result, a.complianceScope)
	return result
}

// SetComplianceScope sets the compliance frameworks.
func (a *Asset) SetComplianceScope(frameworks []string) {
	if frameworks == nil {
		frameworks = make([]string, 0)
	}
	a.complianceScope = frameworks
	a.updatedAt = time.Now().UTC()
}

// AddComplianceFramework adds a compliance framework to scope.
func (a *Asset) AddComplianceFramework(framework string) {
	if framework == "" {
		return
	}
	for _, f := range a.complianceScope {
		if f == framework {
			return
		}
	}
	a.complianceScope = append(a.complianceScope, framework)
	a.updatedAt = time.Now().UTC()
}

// RemoveComplianceFramework removes a compliance framework from scope.
func (a *Asset) RemoveComplianceFramework(framework string) {
	for i, f := range a.complianceScope {
		if f == framework {
			a.complianceScope = append(a.complianceScope[:i], a.complianceScope[i+1:]...)
			a.updatedAt = time.Now().UTC()
			return
		}
	}
}

// IsInComplianceScope checks if asset is in scope for a framework.
func (a *Asset) IsInComplianceScope(framework string) bool {
	for _, f := range a.complianceScope {
		if f == framework {
			return true
		}
	}
	return false
}

// DataClassification returns the data classification level.
func (a *Asset) DataClassification() DataClassification {
	return a.dataClassification
}

// SetDataClassification sets the data classification level.
func (a *Asset) SetDataClassification(classification DataClassification) error {
	if classification != "" && !classification.IsValid() {
		return fmt.Errorf("%w: invalid data classification", shared.ErrValidation)
	}
	a.dataClassification = classification
	a.updatedAt = time.Now().UTC()
	return nil
}

// PIIDataExposed returns whether PII data is exposed.
func (a *Asset) PIIDataExposed() bool {
	return a.piiDataExposed
}

// SetPIIDataExposed sets whether PII data is exposed.
func (a *Asset) SetPIIDataExposed(exposed bool) {
	a.piiDataExposed = exposed
	a.updatedAt = time.Now().UTC()
}

// PHIDataExposed returns whether PHI data is exposed.
func (a *Asset) PHIDataExposed() bool {
	return a.phiDataExposed
}

// SetPHIDataExposed sets whether PHI data is exposed.
func (a *Asset) SetPHIDataExposed(exposed bool) {
	a.phiDataExposed = exposed
	a.updatedAt = time.Now().UTC()
}

// RegulatoryOwnerID returns the regulatory owner user ID.
func (a *Asset) RegulatoryOwnerID() *shared.ID {
	return a.regulatoryOwnerID
}

// SetRegulatoryOwnerID sets the regulatory owner user ID.
func (a *Asset) SetRegulatoryOwnerID(ownerID *shared.ID) {
	a.regulatoryOwnerID = ownerID
	a.updatedAt = time.Now().UTC()
}

// =============================================================================
// CTEM: Enhanced Exposure Tracking Methods
// =============================================================================

// IsInternetAccessible returns whether the asset is directly internet accessible.
func (a *Asset) IsInternetAccessible() bool {
	return a.isInternetAccessible
}

// SetInternetAccessible sets whether the asset is internet accessible.
func (a *Asset) SetInternetAccessible(accessible bool) {
	a.isInternetAccessible = accessible
	a.updatedAt = time.Now().UTC()
}

// ExposureChangedAt returns when the exposure level last changed.
func (a *Asset) ExposureChangedAt() *time.Time {
	return a.exposureChangedAt
}

// LastExposureLevel returns the previous exposure level.
func (a *Asset) LastExposureLevel() Exposure {
	return a.lastExposureLevel
}

// UpdateExposureWithTracking updates exposure and tracks the change.
func (a *Asset) UpdateExposureWithTracking(newExposure Exposure) error {
	if !newExposure.IsValid() {
		return fmt.Errorf("%w: invalid exposure", shared.ErrValidation)
	}
	if a.exposure != newExposure {
		a.lastExposureLevel = a.exposure
		now := time.Now().UTC()
		a.exposureChangedAt = &now
		a.exposure = newExposure
		a.updatedAt = now
	}
	return nil
}

// HasSensitiveData returns true if asset contains PII or PHI data.
func (a *Asset) HasSensitiveData() bool {
	return a.piiDataExposed || a.phiDataExposed
}

// IsHighRiskCompliance returns true if asset is in high-risk compliance scope.
func (a *Asset) IsHighRiskCompliance() bool {
	highRiskFrameworks := []string{"PCI-DSS", "HIPAA", "SOC2"}
	for _, framework := range highRiskFrameworks {
		if a.IsInComplianceScope(framework) {
			return true
		}
	}
	return false
}

// CTEMRiskFactor returns a risk multiplier based on CTEM factors.
func (a *Asset) CTEMRiskFactor() float64 {
	factor := 1.0

	// Internet accessible increases risk
	if a.isInternetAccessible {
		factor *= 1.5
	}

	// Sensitive data increases risk
	if a.piiDataExposed {
		factor *= 1.3
	}
	if a.phiDataExposed {
		factor *= 1.4
	}

	// High-risk compliance increases risk
	if a.IsHighRiskCompliance() {
		factor *= 1.2
	}

	// Restricted/Secret classification increases risk
	if a.dataClassification == DataClassificationRestricted || a.dataClassification == DataClassificationSecret {
		factor *= 1.3
	}

	return factor
}
