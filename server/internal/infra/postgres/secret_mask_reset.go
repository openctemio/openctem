package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// SecretMaskResetReport is the outcome of ResetMaskSecretFingerprints for one
// tenant. It holds counts only: no fingerprint, preview or snippet.
type SecretMaskResetReport struct {
	TenantID string `json:"tenant_id"`
	Applied  bool   `json:"applied"`
	// Fingerprints is the number of secret findings whose fingerprint was
	// derived from a mask (a dry run counts them).
	Fingerprints int `json:"fingerprints"`
	// Previews is the number of secret findings whose stored preview is the
	// word REDACTED reduced to "RE…ED".
	Previews int `json:"previews"`
	// GroupedRotationTasks is the number of rotation tasks that group more
	// than one of the affected findings. They keep their history but lose
	// auto-join; nothing is split. For the owner to review.
	GroupedRotationTasks int `json:"grouped_rotation_tasks"`
	// Remaining is what an applied run could not reach because another
	// transaction held the row; run it again.
	Remaining int `json:"remaining"`
	// FindingIDs are the findings an applied run changed, for the caller to
	// re-derive their remediation keys. Never printed.
	FindingIDs []shared.ID `json:"-"`
}

const (
	maskFingerprintWhere = `tenant_id = $1::uuid AND finding_type = 'secret' AND created_at < $2
		  AND COALESCE(type_details->'secret'->>'fingerprint', '') <> ''`
	// maskPreviewWhere: the preview the API produced from the literal word
	// REDACTED (first and last 2 characters around an ellipsis).
	maskPreviewWhere = `tenant_id = $1::uuid AND finding_type = 'secret'
		  AND type_details->'secret'->>'masked_preview' = 'RE…ED'`
)

// The batch statements take the batch size as their last parameter.
const (
	clearMaskFingerprintSQL = `
		WITH batch AS (
			SELECT id FROM findings WHERE ` + maskFingerprintWhere + `
			LIMIT $3
			FOR UPDATE SKIP LOCKED
		)
		UPDATE findings f SET type_details = f.type_details #- '{secret,fingerprint}'
		FROM batch WHERE f.id = batch.id AND f.tenant_id = $1::uuid
		RETURNING f.id`
	clearMaskPreviewSQL = `
		WITH batch AS (
			SELECT id FROM findings WHERE ` + maskPreviewWhere + `
			LIMIT $2
			FOR UPDATE SKIP LOCKED
		)
		UPDATE findings f SET type_details = f.type_details #- '{secret,masked_preview}'
		FROM batch WHERE f.id = batch.id AND f.tenant_id = $1::uuid
		RETURNING f.id`
)

// clearBatches runs one of the statements above until a batch comes back
// short, collecting the ids it changed.
func clearBatches(ctx context.Context, db *sql.DB, query string, batchSize int, seen map[shared.ID]struct{}, args ...any) (int, error) {
	total := 0
	for {
		n, err := clearBatch(ctx, db, query, batchSize, seen, args)
		total += n
		if err != nil || n < batchSize {
			return total, err
		}
	}
}

func clearBatch(ctx context.Context, db *sql.DB, query string, batchSize int, seen map[shared.ID]struct{}, args []any) (int, error) {
	rows, err := db.QueryContext(ctx, query, append(append([]any{}, args...), batchSize)...)
	if err != nil {
		return 0, err
	}
	defer func() { _ = rows.Close() }()
	n := 0
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return n, err
		}
		if id, err := shared.IDFromString(s); err == nil {
			seen[id] = struct{}{}
		}
		n++
	}
	return n, rows.Err()
}

// MaskSecretResetTenants lists the tenants that hold a secret fingerprint
// created before the cutoff or a "RE…ED" preview (optionally only tenantID).
func MaskSecretResetTenants(ctx context.Context, db *sql.DB, tenantID *shared.ID, before time.Time) ([]shared.ID, error) {
	var tenant any
	if tenantID != nil {
		tenant = tenantID.String()
	}
	rows, err := db.QueryContext(ctx, `
		SELECT DISTINCT tenant_id FROM findings
		WHERE finding_type = 'secret' AND ($1::uuid IS NULL OR tenant_id = $1::uuid)
		  AND ((created_at < $2 AND COALESCE(type_details->'secret'->>'fingerprint', '') <> '')
		       OR type_details->'secret'->>'masked_preview' = 'RE…ED')`, tenant, before)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []shared.ID
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		if id, err := shared.IDFromString(s); err == nil {
			out = append(out, id)
		}
	}
	return out, rows.Err()
}

// ResetMaskSecretFingerprints clears, for one tenant, the secret fingerprints
// created before the cutoff and turns stored "RE…ED" previews into none.
//
// Until the rotation-group fix every secret fingerprint was derived from the
// scanner's mask, and every short secret masks to "REDACTED", so unrelated
// secrets share one rotation group. A mask cannot be turned back into the
// secret, so the fingerprints are dropped: the next sighting that carries a
// keyed hash of the raw value writes the real one (Finding.EnrichFrom fills a
// fingerprint only while it is empty). before must be the time the fix was
// deployed: later fingerprints come from the raw value and must stay.
//
// Only finding_type = 'secret' rows of tenantID change. It runs in batches
// that skip rows another transaction holds, and a dry run (apply false)
// only counts. The caller then re-derives the remediation keys of
// report.FindingIDs.
func ResetMaskSecretFingerprints(ctx context.Context, db *sql.DB, tenantID shared.ID, before time.Time, apply bool, batchSize int) (*SecretMaskResetReport, error) {
	if batchSize <= 0 {
		return nil, fmt.Errorf("batch size must be positive")
	}
	if tenantID.IsZero() {
		return nil, fmt.Errorf("a tenant is required")
	}
	t := tenantID.String()
	rep := &SecretMaskResetReport{TenantID: t, Applied: apply}

	// Grouped rotation tasks are counted before anything changes.
	if err := db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM (
			SELECT m.task_id
			FROM remediation_task_members m
			JOIN remediation_tasks rt ON rt.tenant_id = m.tenant_id AND rt.id = m.task_id
			JOIN remediation_actions ra ON ra.tenant_id = rt.tenant_id AND ra.id = rt.action_id
			JOIN findings f ON f.tenant_id = m.tenant_id AND f.id = m.finding_id
			WHERE m.tenant_id = $1::uuid AND m.left_at IS NULL AND ra.kind = 'rotate'
			  AND rt.state NOT IN ('canceled', 'archived')
			  AND f.finding_type = 'secret'
			  AND ((f.created_at < $2 AND COALESCE(f.type_details->'secret'->>'fingerprint', '') <> '')
			       OR f.type_details->'secret'->>'masked_preview' = 'RE…ED')
			GROUP BY m.task_id HAVING COUNT(*) > 1) g`, t, before).Scan(&rep.GroupedRotationTasks); err != nil {
		return nil, err
	}

	if !apply {
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM findings WHERE `+maskFingerprintWhere, t, before).Scan(&rep.Fingerprints); err != nil {
			return nil, err
		}
		err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM findings WHERE `+maskPreviewWhere, t).Scan(&rep.Previews)
		return rep, err
	}

	seen := map[shared.ID]struct{}{}
	var err error
	if rep.Fingerprints, err = clearBatches(ctx, db, clearMaskFingerprintSQL, batchSize, seen, t, before); err != nil {
		return rep, fmt.Errorf("clear mask-derived secret fingerprints: %w", err)
	}
	if rep.Previews, err = clearBatches(ctx, db, clearMaskPreviewSQL, batchSize, seen, t); err != nil {
		return rep, fmt.Errorf("clear REDACTED previews: %w", err)
	}
	for id := range seen {
		rep.FindingIDs = append(rep.FindingIDs, id)
	}
	var left, leftPv int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM findings WHERE `+maskFingerprintWhere, t, before).Scan(&left); err != nil {
		return rep, err
	}
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM findings WHERE `+maskPreviewWhere, t).Scan(&leftPv); err != nil {
		return rep, err
	}
	rep.Remaining = left + leftPv
	return rep, nil
}
