package postgres

// "Mark duplicate of" storage (RFC-043 §9).
// https://github.com/openctemio/openctem/blob/develop/api/docs/rfcs/RFC-043-deduplication-and-identity.md
//
// A user folds a finding into another through the same merge an asset merge
// and the re-fingerprint job use: the canonical finding inherits the stronger
// state, every row that references the duplicate (comments, activities,
// retests, evidence, approvals, …) moves to it, the duplicate's keys become
// its aliases, and the duplicate stays as a tombstone (status = duplicate,
// duplicate_of). Nothing is deleted.

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// MarkDuplicateOf folds duplicateID into canonicalID, both of tenantID, in one
// transaction. Both rows are locked (in id order, so two opposite requests
// cannot deadlock) and the duplicate rules are checked again under the lock,
// so a concurrent change cannot slip past the checks the caller made. A
// finding that is not in the tenant is not found.
func (r *FindingRepository) MarkDuplicateOf(ctx context.Context, tenantID, duplicateID, canonicalID shared.ID, actorID string, canApprove bool) error {
	tenant := tenantID.String()
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin mark duplicate: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	found, err := lockDuplicateCandidates(ctx, tx, tenant, duplicateID, canonicalID)
	if err != nil {
		return err
	}
	dup, ok := found[duplicateID.String()]
	if !ok {
		return vulnerability.FindingNotFoundError(duplicateID)
	}
	canonical, ok := found[canonicalID.String()]
	if !ok && duplicateID != canonicalID {
		return vulnerability.FindingNotFoundError(canonicalID)
	}
	if duplicateID == canonicalID {
		canonical = dup
	}
	if err := vulnerability.CheckMarkDuplicate(dup, canonical, canApprove); err != nil {
		return err
	}

	cause := findingMergeCause{Reason: "manual", Phrase: "by a user", ActorType: "user", ActorID: actorID}
	if _, err := shared.IDFromString(actorID); err != nil {
		cause.ActorType, cause.ActorID = "system", ""
	}
	if err := mergeFindingInto(ctx, tx, tenant, canonicalID.String(), duplicateID.String(), cause); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit mark duplicate: %w", err)
	}
	return nil
}

// lockDuplicateCandidates locks the two findings of the tenant, in id order,
// and returns them by id; a finding not in the tenant is absent.
func lockDuplicateCandidates(ctx context.Context, tx *sql.Tx, tenant string, ids ...shared.ID) (map[string]vulnerability.DuplicateCandidate, error) {
	strs := make([]string, 0, len(ids))
	for _, id := range ids {
		strs = append(strs, id.String())
	}
	rows, err := tx.QueryContext(ctx, `
		SELECT id, COALESCE(asset_id::text, ''), status, source
		FROM findings
		WHERE tenant_id = $1 AND id = ANY($2::uuid[])
		ORDER BY id
		FOR UPDATE`, tenant, pq.Array(strs))
	if err != nil {
		return nil, fmt.Errorf("lock findings to merge: %w", err)
	}
	defer func() { _ = rows.Close() }()
	found := map[string]vulnerability.DuplicateCandidate{}
	for rows.Next() {
		var id, asset, status, source string
		if err := rows.Scan(&id, &asset, &status, &source); err != nil {
			return nil, fmt.Errorf("scan finding to merge: %w", err)
		}
		c := vulnerability.DuplicateCandidate{Status: vulnerability.FindingStatus(status), Source: vulnerability.FindingSource(source)}
		c.ID, _ = shared.IDFromString(id)
		c.AssetID, _ = shared.IDFromString(asset)
		found[id] = c
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read findings to merge: %w", err)
	}
	return found, nil
}
