package asset

import (
	"fmt"
	"slices"
	"strings"
)

// AssetType represents the type of an asset.
type AssetType string

const (
	// Discovery/External Attack Surface
	AssetTypeDomain      AssetType = "domain"
	AssetTypeSubdomain   AssetType = "subdomain"
	AssetTypeCertificate AssetType = "certificate"
	AssetTypeIPAddress   AssetType = "ip_address"

	// Applications
	AssetTypeWebsite        AssetType = "website"
	AssetTypeWebApplication AssetType = "web_application"
	AssetTypeAPI            AssetType = "api"
	AssetTypeMobileApp      AssetType = "mobile_app"
	AssetTypeService        AssetType = "service" // Network services (SSH, HTTP, DB, etc.)

	// Code/Repository
	AssetTypeRepository AssetType = "repository"

	// Cloud
	AssetTypeCloudAccount      AssetType = "cloud_account"
	AssetTypeCompute           AssetType = "compute"
	AssetTypeStorage           AssetType = "storage"
	AssetTypeServerless        AssetType = "serverless"
	AssetTypeContainerRegistry AssetType = "container_registry"

	// Infrastructure
	AssetTypeHost                AssetType = "host"
	AssetTypeContainer           AssetType = "container"
	AssetTypeKubernetesCluster   AssetType = "kubernetes_cluster"
	AssetTypeKubernetesNamespace AssetType = "kubernetes_namespace"

	// Data
	AssetTypeDatabase  AssetType = "database"
	AssetTypeDataStore AssetType = "data_store"
	AssetTypeS3Bucket  AssetType = "s3_bucket"

	// Network
	AssetTypeNetwork      AssetType = "network"
	AssetTypeVPC          AssetType = "vpc"
	AssetTypeSubnet       AssetType = "subnet"
	AssetTypeLoadBalancer AssetType = "load_balancer"
	AssetTypeFirewall     AssetType = "firewall"

	// Identity
	AssetTypeIAMUser        AssetType = "iam_user"
	AssetTypeIAMRole        AssetType = "iam_role"
	AssetTypeServiceAccount AssetType = "service_account"

	// Unclassified assets
	AssetTypeUnclassified AssetType = "unclassified"

	// Recon-specific types
	AssetTypeHTTPService   AssetType = "http_service"   // HTTP/HTTPS services from HTTPX
	AssetTypeOpenPort      AssetType = "open_port"      // Individual open ports from Naabu
	AssetTypeDiscoveredURL AssetType = "discovered_url" // URLs/endpoints from Katana

	// Endpoint — first-class endpoint asset. An endpoint is a
	// physical/virtual user-operated device (laptop, workstation, mobile
	// handset, kiosk). Distinct from Host (server infra) because
	// endpoints live in the human-operated edge of the attack surface
	// where phishing-executed malware and stolen credentials land
	// first, and where runtime telemetry (EDR, XDR) is emitted.
	//
	// Treated as its own core type (not a Host sub-type) because:
	//   - Priority / SLA policies differ (endpoint compromise ≠ server
	//     compromise: exposure scope, regulated-data proximity).
	//   - Runtime telemetry ingest (#343) flows through endpoints.
	//   - CTEM maturity dashboards report endpoint coverage separately.
	AssetTypeEndpoint AssetType = "endpoint"

	// Consolidated types (new core types)
	AssetTypeApplication AssetType = "application" // Consolidates website, web_application, api, mobile_app
	AssetTypeIdentity    AssetType = "identity"    // Consolidates iam_user, iam_role, service_account
	AssetTypeKubernetes  AssetType = "kubernetes"  // Consolidates kubernetes_cluster, kubernetes_namespace
)

// TypeAliases maps legacy types to their consolidated core type + sub_type.
// Used by ingest processor to normalize incoming data.
var TypeAliases = map[AssetType]struct {
	CoreType AssetType
	SubType  string
}{
	"firewall":             {CoreType: AssetTypeNetwork, SubType: "firewall"},
	"load_balancer":        {CoreType: AssetTypeNetwork, SubType: "load_balancer"},
	"vpc":                  {CoreType: AssetTypeNetwork, SubType: "vpc"},
	"subnet":               {CoreType: AssetTypeNetwork, SubType: "subnet"},
	"compute":              {CoreType: AssetTypeHost, SubType: "compute"},
	"serverless":           {CoreType: AssetTypeHost, SubType: "serverless"},
	"website":              {CoreType: AssetTypeApplication, SubType: "website"},
	"web_application":      {CoreType: AssetTypeApplication, SubType: "web_application"},
	"api":                  {CoreType: AssetTypeApplication, SubType: "api"},
	"mobile_app":           {CoreType: AssetTypeApplication, SubType: "mobile_app"},
	"iam_user":             {CoreType: AssetTypeIdentity, SubType: "iam_user"},
	"iam_role":             {CoreType: AssetTypeIdentity, SubType: "iam_role"},
	"service_account":      {CoreType: AssetTypeIdentity, SubType: "service_account"},
	"data_store":           {CoreType: AssetTypeDatabase, SubType: "data_store"},
	"s3_bucket":            {CoreType: AssetTypeStorage, SubType: "s3_bucket"},
	"container_registry":   {CoreType: AssetTypeStorage, SubType: "container_registry"},
	"kubernetes_cluster":   {CoreType: AssetTypeKubernetes, SubType: "cluster"},
	"kubernetes_namespace": {CoreType: AssetTypeKubernetes, SubType: "namespace"},
	"http_service":         {CoreType: AssetTypeService, SubType: "http"},
	"open_port":            {CoreType: AssetTypeService, SubType: "open_port"},
	"discovered_url":       {CoreType: AssetTypeService, SubType: "discovered_url"},
}

// ResolveTypeAlias resolves a legacy type to its core type + sub_type.
// If no alias exists, returns the original type with empty sub_type.
func ResolveTypeAlias(t AssetType) (coreType AssetType, subType string) {
	if alias, ok := TypeAliases[t]; ok {
		return alias.CoreType, alias.SubType
	}
	return t, ""
}

// AllAssetTypes returns all valid asset types (including legacy for backward compat).
func AllAssetTypes() []AssetType {
	return []AssetType{
		// Discovery/External Attack Surface
		AssetTypeDomain,
		AssetTypeSubdomain,
		AssetTypeCertificate,
		AssetTypeIPAddress,
		// Applications
		AssetTypeWebsite,
		AssetTypeWebApplication,
		AssetTypeAPI,
		AssetTypeMobileApp,
		AssetTypeService,
		// Code/Repository
		AssetTypeRepository,
		// Cloud
		AssetTypeCloudAccount,
		AssetTypeCompute,
		AssetTypeStorage,
		AssetTypeServerless,
		AssetTypeContainerRegistry,
		// Infrastructure
		AssetTypeHost,
		AssetTypeContainer,
		AssetTypeKubernetesCluster,
		AssetTypeKubernetesNamespace,
		AssetTypeEndpoint,
		// Data
		AssetTypeDatabase,
		AssetTypeDataStore,
		AssetTypeS3Bucket,
		// Network
		AssetTypeNetwork,
		AssetTypeVPC,
		AssetTypeSubnet,
		AssetTypeLoadBalancer,
		AssetTypeFirewall,
		// Identity
		AssetTypeIAMUser,
		AssetTypeIAMRole,
		AssetTypeServiceAccount,
		// Unclassified
		AssetTypeUnclassified,
		// Recon-specific
		AssetTypeHTTPService,
		AssetTypeOpenPort,
		AssetTypeDiscoveredURL,
		// Consolidated core types
		AssetTypeApplication,
		AssetTypeIdentity,
		AssetTypeKubernetes,
	}
}

// IsRepository returns true if the asset type is a code repository.
func (t AssetType) IsRepository() bool {
	return t == AssetTypeRepository
}

// SyncStatus represents the synchronization status of an asset.
type SyncStatus string

const (
	SyncStatusSynced   SyncStatus = "synced"
	SyncStatusPending  SyncStatus = "pending"
	SyncStatusSyncing  SyncStatus = "syncing"
	SyncStatusError    SyncStatus = "error"
	SyncStatusDisabled SyncStatus = "disabled"
)

// AllSyncStatuses returns all valid sync statuses.
func AllSyncStatuses() []SyncStatus {
	return []SyncStatus{
		SyncStatusSynced,
		SyncStatusPending,
		SyncStatusSyncing,
		SyncStatusError,
		SyncStatusDisabled,
	}
}

// IsValid checks if the sync status is valid.
func (s SyncStatus) IsValid() bool {
	return slices.Contains(AllSyncStatuses(), s)
}

// String returns the string representation.
func (s SyncStatus) String() string {
	return string(s)
}

// ParseSyncStatus parses a string into a SyncStatus.
func ParseSyncStatus(str string) SyncStatus {
	s := SyncStatus(strings.ToLower(strings.TrimSpace(str)))
	if !s.IsValid() {
		return SyncStatusSynced
	}
	return s
}

// Provider represents the external provider of an asset.
type Provider string

const (
	ProviderGitHub      Provider = "github"
	ProviderGitLab      Provider = "gitlab"
	ProviderBitbucket   Provider = "bitbucket"
	ProviderAzureDevOps Provider = "azure_devops"
	ProviderAWS         Provider = "aws"
	ProviderAzure       Provider = "azure"
	ProviderGCP         Provider = "gcp"
	ProviderManual      Provider = "manual"
	ProviderOther       Provider = "other"
)

// AllProviders returns all valid providers.
func AllProviders() []Provider {
	return []Provider{
		ProviderGitHub,
		ProviderGitLab,
		ProviderBitbucket,
		ProviderAzureDevOps,
		ProviderAWS,
		ProviderAzure,
		ProviderGCP,
		ProviderManual,
		ProviderOther,
	}
}

// IsValid checks if the provider is valid.
func (p Provider) IsValid() bool {
	return slices.Contains(AllProviders(), p)
}

// String returns the string representation.
func (p Provider) String() string {
	return string(p)
}

// ParseProvider parses a string into a Provider.
func ParseProvider(str string) Provider {
	p := Provider(strings.ToLower(strings.TrimSpace(str)))
	if !p.IsValid() {
		return ProviderOther
	}
	return p
}

// IsSCM returns true if the provider is a source code management provider.
func (p Provider) IsSCM() bool {
	return p == ProviderGitHub || p == ProviderGitLab || p == ProviderBitbucket || p == ProviderAzureDevOps
}

// IsCloud returns true if the provider is a cloud provider.
func (p Provider) IsCloud() bool {
	return p == ProviderAWS || p == ProviderAzure || p == ProviderGCP
}

// ParseClassification parses a classification string.
// Classification is a free-form string, so this just trims whitespace.
func ParseClassification(s string) string {
	return strings.TrimSpace(s)
}

// IsValid checks if the asset type is valid.
func (t AssetType) IsValid() bool {
	return slices.Contains(AllAssetTypes(), t)
}

// String returns the string representation.
func (t AssetType) String() string {
	return string(t)
}

// ParseAssetType parses a string into an AssetType.
func ParseAssetType(s string) (AssetType, error) {
	t := AssetType(strings.ToLower(strings.TrimSpace(s)))
	if !t.IsValid() {
		return "", fmt.Errorf("invalid asset type: %s", s)
	}
	return t, nil
}

// Criticality represents the criticality level of an asset.
type Criticality string

const (
	CriticalityCritical Criticality = "critical"
	CriticalityHigh     Criticality = "high"
	CriticalityMedium   Criticality = "medium"
	CriticalityLow      Criticality = "low"
	CriticalityNone     Criticality = "none"
)

// AllCriticalities returns all valid criticality levels.
func AllCriticalities() []Criticality {
	return []Criticality{
		CriticalityCritical,
		CriticalityHigh,
		CriticalityMedium,
		CriticalityLow,
		CriticalityNone,
	}
}

// IsValid checks if the criticality is valid.
func (c Criticality) IsValid() bool {
	return slices.Contains(AllCriticalities(), c)
}

// String returns the string representation.
func (c Criticality) String() string {
	return string(c)
}

// Score returns the numeric score for the criticality (0-100).
func (c Criticality) Score() int {
	switch c {
	case CriticalityCritical:
		return 100
	case CriticalityHigh:
		return 75
	case CriticalityMedium:
		return 50
	case CriticalityLow:
		return 25
	case CriticalityNone:
		return 0
	default:
		return 0
	}
}

// ParseCriticality parses a string into a Criticality.
func ParseCriticality(s string) (Criticality, error) {
	c := Criticality(strings.ToLower(strings.TrimSpace(s)))
	if !c.IsValid() {
		return "", fmt.Errorf("invalid criticality: %s", s)
	}
	return c, nil
}

// Status represents the status of an asset.
type Status string

const (
	StatusActive Status = "active"
	// StatusStale marks an asset that has not been re-observed by any
	// scanner/integration within the tenant's lifecycle threshold but
	// is not yet demoted to inactive. Operators see a UI warning and
	// the asset still appears in default lists. Findings on a stale
	// asset keep running their SLAs — the exposure may still exist in
	// the real world. Set by the lifecycle background worker.
	StatusStale    Status = "stale"
	StatusInactive Status = "inactive"
	StatusArchived Status = "archived"
)

// AllStatuses returns all valid statuses.
func AllStatuses() []Status {
	return []Status{
		StatusActive,
		StatusStale,
		StatusInactive,
		StatusArchived,
	}
}

// IsValid checks if the status is valid.
func (s Status) IsValid() bool {
	return slices.Contains(AllStatuses(), s)
}

// String returns the string representation.
func (s Status) String() string {
	return string(s)
}

// ParseStatus parses a string into a Status.
func ParseStatus(str string) (Status, error) {
	s := Status(strings.ToLower(strings.TrimSpace(str)))
	if !s.IsValid() {
		return "", fmt.Errorf("invalid status: %s", str)
	}
	return s, nil
}

// Scope represents the ownership classification of an asset.
type Scope string

const (
	ScopeInternal Scope = "internal" // Owned and managed internally
	ScopeExternal Scope = "external" // External-facing assets
	ScopeCloud    Scope = "cloud"    // Cloud-hosted assets
	ScopePartner  Scope = "partner"  // Partner-managed assets
	ScopeVendor   Scope = "vendor"   // Vendor/third-party assets
	ScopeShadow   Scope = "shadow"   // Unknown/shadow IT assets
)

// AllScopes returns all valid scopes.
func AllScopes() []Scope {
	return []Scope{
		ScopeInternal,
		ScopeExternal,
		ScopeCloud,
		ScopePartner,
		ScopeVendor,
		ScopeShadow,
	}
}

// IsValid checks if the scope is valid.
func (s Scope) IsValid() bool {
	return slices.Contains(AllScopes(), s)
}

// String returns the string representation.
func (s Scope) String() string {
	return string(s)
}

// ParseScope parses a string into a Scope.
func ParseScope(str string) (Scope, error) {
	s := Scope(strings.ToLower(strings.TrimSpace(str)))
	if !s.IsValid() {
		return "", fmt.Errorf("invalid scope: %s", str)
	}
	return s, nil
}

// Exposure represents the network accessibility level of an asset.
type Exposure string

const (
	ExposurePublic     Exposure = "public"     // Publicly accessible from internet
	ExposureRestricted Exposure = "restricted" // Restricted access (VPN, IP whitelist)
	ExposurePrivate    Exposure = "private"    // Internal network only
	ExposureIsolated   Exposure = "isolated"   // Air-gapped or highly isolated
	ExposureUnknown    Exposure = "unknown"    // Unknown exposure level
)

// AllExposures returns all valid exposure levels.
func AllExposures() []Exposure {
	return []Exposure{
		ExposurePublic,
		ExposureRestricted,
		ExposurePrivate,
		ExposureIsolated,
		ExposureUnknown,
	}
}

// IsValid checks if the exposure is valid.
func (e Exposure) IsValid() bool {
	return slices.Contains(AllExposures(), e)
}

// String returns the string representation.
func (e Exposure) String() string {
	return string(e)
}

// ParseExposure parses a string into an Exposure.
func ParseExposure(str string) (Exposure, error) {
	e := Exposure(strings.ToLower(strings.TrimSpace(str)))
	if !e.IsValid() {
		return "", fmt.Errorf("invalid exposure: %s", str)
	}
	return e, nil
}

// ExposureMultiplier returns the risk multiplier for the exposure level.
func (e Exposure) ExposureMultiplier() float64 {
	switch e {
	case ExposurePublic:
		return 1.5
	case ExposureRestricted:
		return 1.2
	case ExposurePrivate:
		return 1.0
	case ExposureIsolated:
		return 0.8
	case ExposureUnknown:
		return 1.0
	default:
		return 1.0
	}
}

// BaseRiskScore returns the base risk score for the exposure level.
func (e Exposure) BaseRiskScore() int {
	switch e {
	case ExposurePublic:
		return 40
	case ExposureRestricted:
		return 25
	case ExposurePrivate:
		return 15
	case ExposureIsolated:
		return 5
	case ExposureUnknown:
		return 20
	default:
		return 20
	}
}

// =============================================================================
// CTEM: Data Classification
// =============================================================================

// DataClassification represents the data classification level of an asset.
type DataClassification string

const (
	DataClassificationPublic       DataClassification = "public"       // Public information, no restrictions
	DataClassificationInternal     DataClassification = "internal"     // Internal use only
	DataClassificationConfidential DataClassification = "confidential" // Confidential, limited access
	DataClassificationRestricted   DataClassification = "restricted"   // Restricted, PII/PHI data
	DataClassificationSecret       DataClassification = "secret"       // Highly sensitive, need-to-know
)

// AllDataClassifications returns all valid data classification levels.
func AllDataClassifications() []DataClassification {
	return []DataClassification{
		DataClassificationPublic,
		DataClassificationInternal,
		DataClassificationConfidential,
		DataClassificationRestricted,
		DataClassificationSecret,
	}
}

// IsValid checks if the data classification is valid.
func (d DataClassification) IsValid() bool {
	return slices.Contains(AllDataClassifications(), d)
}

// String returns the string representation.
func (d DataClassification) String() string {
	return string(d)
}

// ParseDataClassification parses a string into a DataClassification.
func ParseDataClassification(str string) (DataClassification, error) {
	if str == "" {
		return "", nil // Empty is allowed (optional field)
	}
	d := DataClassification(strings.ToLower(strings.TrimSpace(str)))
	if !d.IsValid() {
		return "", fmt.Errorf("invalid data classification: %s", str)
	}
	return d, nil
}

// RiskMultiplier returns the risk multiplier for the data classification.
func (d DataClassification) RiskMultiplier() float64 {
	switch d {
	case DataClassificationSecret:
		return 2.0
	case DataClassificationRestricted:
		return 1.7
	case DataClassificationConfidential:
		return 1.4
	case DataClassificationInternal:
		return 1.1
	case DataClassificationPublic:
		return 1.0
	default:
		return 1.0
	}
}

// RequiresEncryption returns true if data at this classification level requires encryption.
func (d DataClassification) RequiresEncryption() bool {
	return d == DataClassificationConfidential || d == DataClassificationRestricted || d == DataClassificationSecret
}

// =============================================================================
// CTEM: Common Compliance Frameworks
// =============================================================================

// ComplianceFramework represents common compliance frameworks.
const (
	ComplianceFrameworkPCIDSS   = "PCI-DSS"
	ComplianceFrameworkHIPAA    = "HIPAA"
	ComplianceFrameworkSOC2     = "SOC2"
	ComplianceFrameworkGDPR     = "GDPR"
	ComplianceFrameworkISO27001 = "ISO27001"
	ComplianceFrameworkNIST     = "NIST"
	ComplianceFrameworkFedRAMP  = "FedRAMP"
	ComplianceFrameworkCCPA     = "CCPA"
)

// AllComplianceFrameworks returns all recognized compliance frameworks.
func AllComplianceFrameworks() []string {
	return []string{
		ComplianceFrameworkPCIDSS,
		ComplianceFrameworkHIPAA,
		ComplianceFrameworkSOC2,
		ComplianceFrameworkGDPR,
		ComplianceFrameworkISO27001,
		ComplianceFrameworkNIST,
		ComplianceFrameworkFedRAMP,
		ComplianceFrameworkCCPA,
	}
}

// IsValidComplianceFramework checks if a framework is recognized.
func IsValidComplianceFramework(framework string) bool {
	return slices.Contains(AllComplianceFrameworks(), framework)
}
