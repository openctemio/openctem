package remediation

import (
	"context"

	"github.com/openctemio/api/pkg/domain/shared"
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

// KeyRepository persists per-finding remediation keys and answers group queries.
// It owns the finding_remediation_keys side-table; it never writes findings.
type KeyRepository interface {
	// Upsert records (or refreshes) a finding's remediation key. Idempotent on
	// finding_id, so re-ingesting a finding keeps its key current.
	Upsert(ctx context.Context, tenantID, findingID shared.ID, key, title string) error

	// Delete removes a finding's key (e.g. when it becomes ungroupable). Deleting
	// the finding itself CASCADE-removes the row.
	Delete(ctx context.Context, findingID shared.ID) error

	// ListGroups returns groups rolled up over the tenant's OPEN findings.
	// excludeStatuses are the closed finding statuses to leave out; pentest
	// findings are always excluded (they own their lifecycle).
	ListGroups(ctx context.Context, tenantID shared.ID, excludeStatuses []string) ([]Group, error)

	// OpenFindingIDs returns the tenant's open, non-pentest finding IDs in a group
	// — the set a "resolve group" action transitions.
	OpenFindingIDs(ctx context.Context, tenantID shared.ID, key string, excludeStatuses []string) ([]shared.ID, error)
}
