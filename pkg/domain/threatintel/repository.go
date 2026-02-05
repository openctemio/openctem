package threatintel

import (
	"context"
)

// EPSSRepository defines the interface for EPSS score persistence.
type EPSSRepository interface {
	// Upsert creates or updates an EPSS score.
	Upsert(ctx context.Context, score *EPSSScore) error

	// UpsertBatch creates or updates multiple EPSS scores.
	UpsertBatch(ctx context.Context, scores []*EPSSScore) error

	// GetByCVEID retrieves an EPSS score by CVE ID.
	GetByCVEID(ctx context.Context, cveID string) (*EPSSScore, error)

	// GetByCVEIDs retrieves EPSS scores for multiple CVE IDs.
	GetByCVEIDs(ctx context.Context, cveIDs []string) ([]*EPSSScore, error)

	// GetHighRisk retrieves all high-risk EPSS scores (score > threshold).
	GetHighRisk(ctx context.Context, threshold float64, limit int) ([]*EPSSScore, error)

	// GetTopPercentile retrieves scores in top N percentile.
	GetTopPercentile(ctx context.Context, percentile float64, limit int) ([]*EPSSScore, error)

	// Count returns the total number of EPSS scores.
	Count(ctx context.Context) (int64, error)

	// DeleteAll removes all EPSS scores (for full refresh).
	DeleteAll(ctx context.Context) error
}

// KEVRepository defines the interface for KEV catalog persistence.
type KEVRepository interface {
	// Upsert creates or updates a KEV entry.
	Upsert(ctx context.Context, entry *KEVEntry) error

	// UpsertBatch creates or updates multiple KEV entries.
	UpsertBatch(ctx context.Context, entries []*KEVEntry) error

	// GetByCVEID retrieves a KEV entry by CVE ID.
	GetByCVEID(ctx context.Context, cveID string) (*KEVEntry, error)

	// GetByCVEIDs retrieves KEV entries for multiple CVE IDs.
	GetByCVEIDs(ctx context.Context, cveIDs []string) ([]*KEVEntry, error)

	// ExistsByCVEID checks if a CVE is in KEV.
	ExistsByCVEID(ctx context.Context, cveID string) (bool, error)

	// ExistsByCVEIDs checks which CVEs are in KEV.
	ExistsByCVEIDs(ctx context.Context, cveIDs []string) (map[string]bool, error)

	// GetPastDue retrieves KEV entries past their due date.
	GetPastDue(ctx context.Context, limit int) ([]*KEVEntry, error)

	// GetRecentlyAdded retrieves recently added KEV entries.
	GetRecentlyAdded(ctx context.Context, days, limit int) ([]*KEVEntry, error)

	// GetRansomwareRelated retrieves KEV entries with known ransomware use.
	GetRansomwareRelated(ctx context.Context, limit int) ([]*KEVEntry, error)

	// Count returns the total number of KEV entries.
	Count(ctx context.Context) (int64, error)

	// DeleteAll removes all KEV entries (for full refresh).
	DeleteAll(ctx context.Context) error
}

// SyncStatusRepository defines the interface for sync status persistence.
type SyncStatusRepository interface {
	// GetBySource retrieves sync status by source name.
	GetBySource(ctx context.Context, source string) (*SyncStatus, error)

	// GetAll retrieves all sync statuses.
	GetAll(ctx context.Context) ([]*SyncStatus, error)

	// GetEnabled retrieves enabled sync statuses.
	GetEnabled(ctx context.Context) ([]*SyncStatus, error)

	// GetDueForSync retrieves sources due for sync.
	GetDueForSync(ctx context.Context) ([]*SyncStatus, error)

	// Update updates a sync status.
	Update(ctx context.Context, status *SyncStatus) error
}

// ThreatIntelRepository combines all threat intel repositories.
type ThreatIntelRepository interface {
	// EPSS returns the EPSS repository.
	EPSS() EPSSRepository

	// KEV returns the KEV repository.
	KEV() KEVRepository

	// SyncStatus returns the sync status repository.
	SyncStatus() SyncStatusRepository

	// EnrichCVEs enriches multiple CVEs with threat intel data.
	EnrichCVEs(ctx context.Context, cveIDs []string) (map[string]*ThreatIntelEnrichment, error)

	// EnrichCVE enriches a single CVE with threat intel data.
	EnrichCVE(ctx context.Context, cveID string) (*ThreatIntelEnrichment, error)
}
