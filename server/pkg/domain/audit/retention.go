package audit

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Audit retention keeps the hash chain verifiable (settings decision B4):
// instead of deleting old rows wherever they sit in the chain (which the
// ON DELETE RESTRICT foreign key from audit_log_chain refused, so retention
// never worked), it prunes the oldest contiguous prefix of a tenant chain:
// archive the rows, record the chain head they leave behind as an anchor,
// then delete them. Verification of the remaining chain starts at the anchor.

// MinAuditRetentionDays is the shortest audit retention the platform accepts.
const MinAuditRetentionDays = 365

// ErrChainPruneConflict means the chain changed between reading the prefix
// and pruning it (an entry was rewritten or the prefix is no longer exactly
// the oldest entries). Nothing was deleted; the next run retries.
var ErrChainPruneConflict = errors.New("audit chain changed while pruning")

// PrunableEntry is one chain entry eligible for pruning, with its audit row
// serialized exactly as stored (for the archive).
type PrunableEntry struct {
	Entry    ChainEntry
	LoggedAt time.Time
	Row      json.RawMessage
}

// ChainAnchor records what one prune removed and the chain head it left.
type ChainAnchor struct {
	TenantID          shared.ID
	AnchorHash        string // hash of the last pruned entry
	LastChainPosition int64
	PrunedCount       int
	OldestLoggedAt    time.Time
	NewestLoggedAt    time.Time
	ArchivePath       string
	ArchiveSHA256     string
}

// ChainAnchorReader returns the prev_hash a tenant's oldest remaining chain
// entry must link to: the newest anchor's hash, or "" when the chain was never
// pruned. Implemented by the Postgres audit repository.
type ChainAnchorReader interface {
	ChainAnchorHash(ctx context.Context, tenantID shared.ID) (string, error)
}

// ChainRetentionRepository is the storage side of retention pruning.
type ChainRetentionRepository interface {
	ChainAnchorReader

	// ChainTenantsWithEntriesBefore lists the chains (tenant ids, including
	// SystemChainTenantID) whose oldest entry was logged before the cutoff.
	ChainTenantsWithEntriesBefore(ctx context.Context, before time.Time) ([]shared.ID, error)

	// ChainPrefixOlderThan returns up to limit of a tenant's oldest chain
	// entries, in chain order, stopping at the first entry logged at or
	// after before (so only a contiguous prefix is ever returned).
	ChainPrefixOlderThan(ctx context.Context, tenantID shared.ID, before time.Time, limit int) ([]PrunableEntry, error)

	// PruneChainPrefix, in one transaction under the chain lock, checks that
	// the given entries are still exactly the tenant's oldest entries and
	// that the last one still carries anchor.AnchorHash, records the anchor
	// and deletes the entries and their audit rows. Returns
	// ErrChainPruneConflict (nothing deleted) when the check fails.
	PruneChainPrefix(ctx context.Context, anchor ChainAnchor, auditLogIDs []shared.ID) error
}
