// Package scanner_template defines the ScannerTemplate domain entity for custom scanner templates.
package scannertemplate

import (
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
)

// TemplateType represents the type of scanner template.
type TemplateType string

const (
	// TemplateTypeNuclei is for Nuclei vulnerability templates (YAML).
	TemplateTypeNuclei TemplateType = "nuclei"
	// TemplateTypeSemgrep is for Semgrep SAST rules (YAML).
	TemplateTypeSemgrep TemplateType = "semgrep"
	// TemplateTypeGitleaks is for Gitleaks secret patterns (TOML).
	TemplateTypeGitleaks TemplateType = "gitleaks"
)

// IsValid checks if the template type is valid.
func (t TemplateType) IsValid() bool {
	switch t {
	case TemplateTypeNuclei, TemplateTypeSemgrep, TemplateTypeGitleaks:
		return true
	}
	return false
}

// FileExtension returns the expected file extension for the template type.
func (t TemplateType) FileExtension() string {
	switch t {
	case TemplateTypeNuclei, TemplateTypeSemgrep:
		return ".yaml"
	case TemplateTypeGitleaks:
		return ".toml"
	default:
		return ""
	}
}

// ContentType returns the expected content type for the template type.
func (t TemplateType) ContentType() string {
	switch t {
	case TemplateTypeNuclei, TemplateTypeSemgrep:
		return "application/x-yaml"
	case TemplateTypeGitleaks:
		return "application/toml"
	default:
		return "application/octet-stream"
	}
}

// MaxSize returns the maximum allowed size in bytes for the template type.
func (t TemplateType) MaxSize() int64 {
	switch t {
	case TemplateTypeNuclei:
		return 1 * 1024 * 1024 // 1MB
	case TemplateTypeSemgrep:
		return 512 * 1024 // 512KB
	case TemplateTypeGitleaks:
		return 256 * 1024 // 256KB
	default:
		return 256 * 1024
	}
}

// MaxRules returns the maximum allowed number of rules for the template type.
func (t TemplateType) MaxRules() int {
	switch t {
	case TemplateTypeNuclei:
		return 100
	case TemplateTypeSemgrep:
		return 500
	case TemplateTypeGitleaks:
		return 1000
	default:
		return 100
	}
}

// Per-tenant template quota constants.
const (
	// DefaultMaxTemplatesPerTenant is the default maximum number of templates per tenant.
	DefaultMaxTemplatesPerTenant = 100

	// DefaultMaxTemplatesPerType is the default maximum number of templates per type per tenant.
	DefaultMaxTemplatesPerType = 50

	// DefaultMaxTotalStorageBytes is the default maximum total storage in bytes per tenant (50MB).
	DefaultMaxTotalStorageBytes = 50 * 1024 * 1024
)

// TemplateQuota represents per-tenant template storage quotas.
type TemplateQuota struct {
	MaxTemplates         int   `json:"max_templates"`           // Max total templates
	MaxTemplatesNuclei   int   `json:"max_templates_nuclei"`    // Max Nuclei templates
	MaxTemplatesSemgrep  int   `json:"max_templates_semgrep"`   // Max Semgrep templates
	MaxTemplatesGitleaks int   `json:"max_templates_gitleaks"`  // Max Gitleaks templates
	MaxTotalStorageBytes int64 `json:"max_total_storage_bytes"` // Max total storage
}

// DefaultQuota returns the default template quota.
func DefaultQuota() TemplateQuota {
	return TemplateQuota{
		MaxTemplates:         DefaultMaxTemplatesPerTenant,
		MaxTemplatesNuclei:   DefaultMaxTemplatesPerType,
		MaxTemplatesSemgrep:  DefaultMaxTemplatesPerType,
		MaxTemplatesGitleaks: DefaultMaxTemplatesPerType,
		MaxTotalStorageBytes: DefaultMaxTotalStorageBytes,
	}
}

// GetMaxForType returns the maximum templates allowed for a specific type.
func (q TemplateQuota) GetMaxForType(templateType TemplateType) int {
	switch templateType {
	case TemplateTypeNuclei:
		return q.MaxTemplatesNuclei
	case TemplateTypeSemgrep:
		return q.MaxTemplatesSemgrep
	case TemplateTypeGitleaks:
		return q.MaxTemplatesGitleaks
	default:
		return 0
	}
}

// TemplateUsage represents current template usage for a tenant.
type TemplateUsage struct {
	TotalTemplates    int64 `json:"total_templates"`
	NucleiTemplates   int64 `json:"nuclei_templates"`
	SemgrepTemplates  int64 `json:"semgrep_templates"`
	GitleaksTemplates int64 `json:"gitleaks_templates"`
	TotalStorageBytes int64 `json:"total_storage_bytes"`
}

// TemplateStatus represents the status of a template.
type TemplateStatus string

const (
	// TemplateStatusActive means the template is active and can be used.
	TemplateStatusActive TemplateStatus = "active"
	// TemplateStatusPendingReview means the template is awaiting review.
	TemplateStatusPendingReview TemplateStatus = "pending_review"
	// TemplateStatusDeprecated means the template is deprecated and should not be used.
	TemplateStatusDeprecated TemplateStatus = "deprecated"
	// TemplateStatusRevoked means the template has been revoked due to security concerns.
	TemplateStatusRevoked TemplateStatus = "revoked"
)

// IsValid checks if the template status is valid.
func (s TemplateStatus) IsValid() bool {
	switch s {
	case TemplateStatusActive, TemplateStatusPendingReview, TemplateStatusDeprecated, TemplateStatusRevoked:
		return true
	}
	return false
}

// IsUsable returns true if the template can be used in scans.
func (s TemplateStatus) IsUsable() bool {
	return s == TemplateStatusActive
}

// SyncSource represents the source of a template.
type SyncSource string

const (
	// SyncSourceManual means the template was uploaded manually.
	SyncSourceManual SyncSource = "manual"
	// SyncSourceGit means the template was synced from a git repository.
	SyncSourceGit SyncSource = "git"
	// SyncSourceS3 means the template was synced from S3/MinIO.
	SyncSourceS3 SyncSource = "s3"
	// SyncSourceHTTP means the template was synced from an HTTP URL.
	SyncSourceHTTP SyncSource = "http"
)

// IsValid checks if the sync source is valid.
func (s SyncSource) IsValid() bool {
	switch s {
	case SyncSourceManual, SyncSourceGit, SyncSourceS3, SyncSourceHTTP:
		return true
	}
	return false
}

// ScannerTemplate represents a custom scanner template (Nuclei, Semgrep, or Gitleaks).
type ScannerTemplate struct {
	ID           shared.ID
	TenantID     shared.ID
	SourceID     *shared.ID // Reference to template source (nil = manual upload)
	Name         string
	TemplateType TemplateType
	Version      string

	// Content storage
	Content       []byte  // Raw YAML/TOML content (inline for <1MB)
	ContentURL    *string // S3 URL for large templates
	ContentHash   string  // SHA256(Content)
	SignatureHash string  // HMAC-SHA256 for verification

	// Metadata
	RuleCount   int
	Description string
	Tags        []string
	Metadata    map[string]any // Scanner-specific metadata

	// Status
	Status          TemplateStatus
	ValidationError *string

	// Source tracking (for synced templates)
	SyncSource   SyncSource // How this template was synced (manual, git, s3, http)
	SourcePath   *string    // Path within source (e.g., templates/sqli.yaml)
	SourceCommit *string    // Git commit hash

	// Audit
	CreatedBy *shared.ID
	CreatedAt time.Time
	UpdatedAt time.Time
}

// NewScannerTemplate creates a new scanner template.
func NewScannerTemplate(
	tenantID shared.ID,
	name string,
	templateType TemplateType,
	content []byte,
	createdBy *shared.ID,
) (*ScannerTemplate, error) {
	if name == "" {
		return nil, shared.NewDomainError("VALIDATION", "name is required", shared.ErrValidation)
	}
	if len(name) > 255 {
		return nil, shared.NewDomainError("VALIDATION", "name must be less than 255 characters", shared.ErrValidation)
	}
	if !templateType.IsValid() {
		return nil, shared.NewDomainError("VALIDATION", "invalid template type", shared.ErrValidation)
	}
	if len(content) == 0 {
		return nil, shared.NewDomainError("VALIDATION", "content is required", shared.ErrValidation)
	}
	if int64(len(content)) > templateType.MaxSize() {
		return nil, shared.NewDomainError("VALIDATION", "content exceeds maximum size", shared.ErrValidation)
	}

	now := time.Now()
	return &ScannerTemplate{
		ID:           shared.NewID(),
		TenantID:     tenantID,
		Name:         name,
		TemplateType: templateType,
		Version:      "1.0.0",
		Content:      content,
		ContentHash:  computeContentHash(content),
		Status:       TemplateStatusActive,
		SyncSource:   SyncSourceManual, // Default to manual upload
		Tags:         []string{},
		Metadata:     make(map[string]any),
		CreatedBy:    createdBy,
		CreatedAt:    now,
		UpdatedAt:    now,
	}, nil
}

// Update updates the template content.
func (t *ScannerTemplate) Update(name, description string, content []byte, tags []string) error {
	if t.Status == TemplateStatusRevoked {
		return shared.NewDomainError("FORBIDDEN", "revoked templates cannot be updated", shared.ErrForbidden)
	}

	if name != "" {
		if len(name) > 255 {
			return shared.NewDomainError("VALIDATION", "name must be less than 255 characters", shared.ErrValidation)
		}
		t.Name = name
	}

	t.Description = description

	if content != nil && len(content) > 0 {
		if int64(len(content)) > t.TemplateType.MaxSize() {
			return shared.NewDomainError("VALIDATION", "content exceeds maximum size", shared.ErrValidation)
		}
		t.Content = content
		t.ContentHash = computeContentHash(content)
		t.IncrementVersion()
	}

	if tags != nil {
		t.Tags = tags
	}

	t.UpdatedAt = time.Now()
	return nil
}

// IncrementVersion increments the patch version.
func (t *ScannerTemplate) IncrementVersion() {
	// Simple version increment: 1.0.0 -> 1.0.1
	// For more sophisticated versioning, use semver library
	t.Version = incrementPatchVersion(t.Version)
}

// SetRuleCount sets the number of rules in the template.
func (t *ScannerTemplate) SetRuleCount(count int) {
	t.RuleCount = count
	t.UpdatedAt = time.Now()
}

// SetValidationError sets the validation error message.
func (t *ScannerTemplate) SetValidationError(err string) {
	t.ValidationError = &err
	t.Status = TemplateStatusPendingReview
	t.UpdatedAt = time.Now()
}

// ClearValidationError clears the validation error.
func (t *ScannerTemplate) ClearValidationError() {
	t.ValidationError = nil
	t.Status = TemplateStatusActive
	t.UpdatedAt = time.Now()
}

// Deprecate marks the template as deprecated.
func (t *ScannerTemplate) Deprecate() {
	t.Status = TemplateStatusDeprecated
	t.UpdatedAt = time.Now()
}

// Revoke marks the template as revoked (security concern).
func (t *ScannerTemplate) Revoke() {
	t.Status = TemplateStatusRevoked
	t.UpdatedAt = time.Now()
}

// Activate marks the template as active.
func (t *ScannerTemplate) Activate() error {
	if t.Status == TemplateStatusRevoked {
		return shared.NewDomainError("FORBIDDEN", "revoked templates cannot be activated", shared.ErrForbidden)
	}
	t.Status = TemplateStatusActive
	t.UpdatedAt = time.Now()
	return nil
}

// SetSignature sets the HMAC signature for the template.
func (t *ScannerTemplate) SetSignature(signature string) {
	t.SignatureHash = signature
	t.UpdatedAt = time.Now()
}

// SetSourceInfo sets the source tracking information.
func (t *ScannerTemplate) SetSourceInfo(sourceID shared.ID, sourcePath, sourceCommit string) {
	t.SourceID = &sourceID
	if sourcePath != "" {
		t.SourcePath = &sourcePath
	}
	if sourceCommit != "" {
		t.SourceCommit = &sourceCommit
	}
	t.UpdatedAt = time.Now()
}

// SetMetadata sets a metadata value.
func (t *ScannerTemplate) SetMetadata(key string, value any) {
	if t.Metadata == nil {
		t.Metadata = make(map[string]any)
	}
	t.Metadata[key] = value
	t.UpdatedAt = time.Now()
}

// IsUsable returns true if the template can be used in scans.
func (t *ScannerTemplate) IsUsable() bool {
	return t.Status.IsUsable()
}

// CanManage checks if the given tenant can manage this template.
func (t *ScannerTemplate) CanManage(tenantID shared.ID) error {
	if !t.TenantID.Equals(tenantID) {
		return shared.NewDomainError("FORBIDDEN", "template belongs to another tenant", shared.ErrForbidden)
	}
	return nil
}

// BelongsToTenant checks if this template belongs to the specified tenant.
func (t *ScannerTemplate) BelongsToTenant(tenantID shared.ID) bool {
	return t.TenantID.Equals(tenantID)
}

// VerifySignature verifies the template signature using the provided secret.
func (t *ScannerTemplate) VerifySignature(secret string) bool {
	if t.SignatureHash == "" {
		return false
	}
	expectedSignature := ComputeSignature(t.Content, secret)
	return t.SignatureHash == expectedSignature
}

// computeContentHash computes the SHA256 hash of the content.
func computeContentHash(content []byte) string {
	hash := sha256.Sum256(content)
	return hex.EncodeToString(hash[:])
}

// incrementPatchVersion increments the patch version of a semver string.
func incrementPatchVersion(version string) string {
	// Simple implementation: just append .1 if no dots, or increment last number
	// For production, use a proper semver library
	if version == "" {
		return "1.0.1"
	}

	// Find last dot
	lastDot := -1
	for i := len(version) - 1; i >= 0; i-- {
		if version[i] == '.' {
			lastDot = i
			break
		}
	}

	if lastDot == -1 {
		return version + ".0.1"
	}

	// Parse patch number
	patchStr := version[lastDot+1:]
	patch := 0
	for _, c := range patchStr {
		if c >= '0' && c <= '9' {
			patch = patch*10 + int(c-'0')
		}
	}

	return version[:lastDot+1] + string(rune('0'+patch+1))
}
