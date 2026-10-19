package remediation

import (
	"context"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Group is one remediation group: the set of open findings a single fix resolves.
type Group struct {
	Key            string         `json:"key"`
	Title          string         `json:"title"`
	FindingCount   int            `json:"finding_count"`
	AssetCount     int            `json:"asset_count"`
	SeverityCounts map[string]int `json:"severity_counts"`
	FixAvailable   bool           `json:"fix_available"`
}

// KeySource is what a finding's key is derived from, read from the finding,
// its package (components) and its CVE catalog entry, plus the key stored now.
type KeySource struct {
	FindingID  shared.ID
	CurrentKey string
	// CurrentTitle is the stored title ("" when no key).
	CurrentTitle string
	// CurrentVersion is the key rules version that derived the stored key
	// (0 when there is none).
	CurrentVersion int
	Input          KeyInput
}

// CampaignKeyRef is a campaign that tracks a remediation key.
type CampaignKeyRef struct {
	ID   shared.ID
	Name string
	Key  string
}

// KeyRepository persists per-finding remediation keys and answers group queries.
// It owns the finding_remediation_keys side-table; it never writes findings.
type KeyRepository interface {
	// Upsert records (or refreshes) a finding's remediation key. Idempotent on
	// finding_id, so re-ingesting a finding keeps its key current.
	Upsert(ctx context.Context, tenantID, findingID shared.ID, key, title string) error

	// Delete removes a finding's key (e.g. when it becomes ungroupable). Deleting
	// the finding itself CASCADE-removes the row.
	Delete(ctx context.Context, tenantID, findingID shared.ID) error

	// HasStaleKeys reports a key derived by an older KeyAlgorithmVersion.
	HasStaleKeys(ctx context.Context, tenantID shared.ID) (bool, error)

	// KeySources reads the signals a key is derived from for the tenant's
	// findings with these ids, with their current key ("" when none). Ids of
	// another tenant or that do not exist are left out.
	KeySources(ctx context.Context, tenantID shared.ID, findingIDs []shared.ID) ([]KeySource, error)

	// KeySourcesByFingerprints is KeySources for the tenant's findings with
	// these fingerprints (a re-sighting at ingest knows the fingerprint).
	KeySourcesByFingerprints(ctx context.Context, tenantID shared.ID, fingerprints []string) ([]KeySource, error)

	// FindingIDsAfter pages through the tenant's finding ids in id order
	// (keyset: ids greater than after; after zero starts at the beginning).
	FindingIDsAfter(ctx context.Context, tenantID, after shared.ID, limit int) ([]shared.ID, error)

	// TenantsWithFindings lists the tenants that have at least one finding.
	TenantsWithFindings(ctx context.Context) ([]shared.ID, error)

	// CampaignsTrackingKeys lists the tenant's campaigns whose finding filter
	// tracks one of these remediation keys.
	CampaignsTrackingKeys(ctx context.Context, tenantID shared.ID, keys []string) ([]CampaignKeyRef, error)

	// CampaignsWithStaleKey lists the tenant's campaigns whose finding filter
	// tracks a remediation key that no finding of the tenant has.
	CampaignsWithStaleKey(ctx context.Context, tenantID shared.ID) ([]CampaignKeyRef, error)

	// RetargetCampaignKey moves one campaign of the tenant from oldKey to
	// newKey. It changes nothing (false) when the campaign no longer tracks
	// oldKey, so a repeated run is a no-op.
	RetargetCampaignKey(ctx context.Context, tenantID, campaignID shared.ID, oldKey, newKey string) (bool, error)

	// ListGroups returns groups rolled up over the tenant's OPEN findings.
	// excludeStatuses are the closed finding statuses to leave out; pentest
	// findings are always excluded (they own their lifecycle). A non-nil scope
	// keeps only findings on assets in that Layer 2 data scope.
	ListGroups(ctx context.Context, tenantID shared.ID, excludeStatuses []string, scope *shared.DataScope) ([]Group, error)

	// OpenFindingIDs returns the tenant's open, non-pentest finding IDs in a group
	// — the set a "resolve group" action transitions — narrowed to scope when
	// it is non-nil.
	OpenFindingIDs(ctx context.Context, tenantID shared.ID, key string, excludeStatuses []string, scope *shared.DataScope) ([]shared.ID, error)

	// CountByKey returns (total, resolved) non-pentest findings sharing the key —
	// total across all statuses, resolved being those in closedStatuses. Used to
	// track a solution-family campaign's progress without a generic FindingFilter.
	CountByKey(ctx context.Context, tenantID shared.ID, key string, closedStatuses []string) (total, resolved int64, err error)
}
