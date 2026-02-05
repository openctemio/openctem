package rule

import (
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
)

// BundleStatus represents the build status of a rule bundle.
type BundleStatus string

const (
	BundleStatusBuilding BundleStatus = "building"
	BundleStatusReady    BundleStatus = "ready"
	BundleStatusFailed   BundleStatus = "failed"
	BundleStatusExpired  BundleStatus = "expired"
)

// Bundle represents a pre-compiled rule package for agents.
// Bundles contain actual YAML files (platform + custom rules) as a tar.gz archive
// stored in object storage (S3/MinIO/local).
//
// Structure inside bundle.tar.gz:
//
//	rules/
//	├── platform/        # Platform default rules
//	│   ├── rule1.yaml
//	│   └── rule2.yaml
//	├── custom/          # Tenant custom rules (all sources merged)
//	│   ├── source1/
//	│   │   └── rule3.yaml
//	│   └── source2/
//	│       └── rule4.yaml
//	└── manifest.json    # Bundle metadata
type Bundle struct {
	ID       shared.ID
	TenantID shared.ID
	ToolID   shared.ID

	// Version info
	Version     string // e.g., "20240115-a1b2c3d4"
	ContentHash string // SHA256 of bundle content (for change detection)

	// Statistics
	RuleCount   int
	SourceCount int
	SizeBytes   int64

	// Sources included
	SourceIDs    []shared.ID
	SourceHashes map[string]string // source_id -> content_hash

	// Storage location
	StoragePath string // S3 key or local path

	// Build status
	Status           BundleStatus
	BuildError       string
	BuildStartedAt   *time.Time
	BuildCompletedAt *time.Time

	CreatedAt time.Time
	ExpiresAt *time.Time
}

// BundleManifest is stored inside the bundle as manifest.json
type BundleManifest struct {
	Version     string            `json:"version"`
	ToolName    string            `json:"tool_name"`
	ContentHash string            `json:"content_hash"`
	CreatedAt   time.Time         `json:"created_at"`
	RuleCount   int               `json:"rule_count"`
	Sources     []BundleSourceRef `json:"sources"`
}

// BundleSourceRef references a source included in the bundle
type BundleSourceRef struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	ContentHash string `json:"content_hash"`
	RuleCount   int    `json:"rule_count"`
	Priority    int    `json:"priority"`
	IsDefault   bool   `json:"is_default"`
}

// NewBundle creates a new bundle.
func NewBundle(tenantID, toolID shared.ID) *Bundle {
	now := time.Now()
	return &Bundle{
		ID:           shared.NewID(),
		TenantID:     tenantID,
		ToolID:       toolID,
		SourceIDs:    []shared.ID{},
		SourceHashes: make(map[string]string),
		Status:       BundleStatusBuilding,
		CreatedAt:    now,
	}
}

// MarkBuildStarted marks the bundle build as started.
func (b *Bundle) MarkBuildStarted() {
	now := time.Now()
	b.Status = BundleStatusBuilding
	b.BuildStartedAt = &now
}

// MarkBuildSuccess marks the bundle build as successful.
func (b *Bundle) MarkBuildSuccess(
	version string,
	hash string,
	storagePath string,
	ruleCount int,
	sizeBytes int64,
	sourceIDs []shared.ID,
	sourceHashes map[string]string,
) {
	now := time.Now()
	b.Version = version
	b.ContentHash = hash
	b.StoragePath = storagePath
	b.RuleCount = ruleCount
	b.SizeBytes = sizeBytes
	b.SourceCount = len(sourceIDs)
	b.SourceIDs = sourceIDs
	b.SourceHashes = sourceHashes
	b.Status = BundleStatusReady
	b.BuildCompletedAt = &now

	// Set expiration (e.g., 7 days for cleanup)
	expires := now.Add(7 * 24 * time.Hour)
	b.ExpiresAt = &expires
}

// MarkBuildFailed marks the bundle build as failed.
func (b *Bundle) MarkBuildFailed(err string) {
	now := time.Now()
	b.Status = BundleStatusFailed
	b.BuildError = err
	b.BuildCompletedAt = &now
}

// IsReady checks if the bundle is ready for download.
func (b *Bundle) IsReady() bool {
	return b.Status == BundleStatusReady
}

// IsExpired checks if the bundle has expired.
func (b *Bundle) IsExpired() bool {
	if b.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*b.ExpiresAt)
}

// NeedsRebuild checks if the bundle needs to be rebuilt based on source hashes.
func (b *Bundle) NeedsRebuild(currentSourceHashes map[string]string) bool {
	if len(b.SourceHashes) != len(currentSourceHashes) {
		return true
	}
	for sourceID, hash := range currentSourceHashes {
		if b.SourceHashes[sourceID] != hash {
			return true
		}
	}
	return false
}
