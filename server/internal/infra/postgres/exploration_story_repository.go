package postgres

// The records a "how we found this" story reads (docs/architecture/exploration.md):
// scan runs and their steps, the runs that derived or targeted an asset, and
// the upload that created it. Every join is bound to the tenant and every
// read returns a bounded number of rows from an index.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/exploration"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// StoryRepository reads the records of a story.
type StoryRepository struct{ db *DB }

var _ exploration.StoryStore = (*StoryRepository)(nil)

// NewStoryRepository creates the repository.
func NewStoryRepository(db *DB) *StoryRepository { return &StoryRepository{db: db} }

// storyMaxRuns bounds the runs one story reads (a finding lists at most
// exploration.MaxReports sources; the cap is defensive).
const storyMaxRuns = 8

// storyScanRunsQuery reads runs $2 (with steps $3, same order) of tenant $1.
// A step is joined only through its own run, which is tenant-bound; the
// scan definition is joined on the tenant too.
const storyScanRunsQuery = `
SELECT r.id::text, s.id::text, r.scan_id::text, COALESCE(sc.name, ''), r.status,
	COALESCE(r.started_at, r.created_at),
	COALESCE(NULLIF(s.step_name, ''), s.step_key, ''), COALESCE(s.capability, ''), COALESCE(s.tool, '')
FROM unnest($2::uuid[], $3::uuid[]) AS q(run_id, step_id)
JOIN scan_runs r ON r.tenant_id = $1 AND r.id = q.run_id
LEFT JOIN scan_run_steps s ON s.id = q.step_id AND s.scan_run_id = r.id
LEFT JOIN scans sc ON sc.tenant_id = $1 AND sc.id = r.scan_id`

// ScanRuns implements exploration.StoryStore.
func (r *StoryRepository) ScanRuns(ctx context.Context, tenantID shared.ID, refs []exploration.RunRef) ([]exploration.ScanStep, error) {
	if len(refs) == 0 {
		return nil, nil
	}
	if len(refs) > storyMaxRuns {
		refs = refs[:storyMaxRuns]
	}
	runs := make([]string, 0, len(refs))
	steps := make([]sql.NullString, 0, len(refs))
	for _, ref := range refs {
		runs = append(runs, ref.RunID.String())
		step := sql.NullString{}
		if ref.StepRunID != nil {
			step = sql.NullString{String: ref.StepRunID.String(), Valid: true}
		}
		steps = append(steps, step)
	}
	rows, err := r.db.QueryContext(ctx, storyScanRunsQuery, tenantID.String(), pq.Array(runs), pq.Array(steps))
	if err != nil {
		return nil, fmt.Errorf("query story runs: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := make([]exploration.ScanStep, 0, len(refs))
	for rows.Next() {
		var (
			s              exploration.ScanStep
			runID          string
			stepID, scanID sql.NullString
			at             time.Time
		)
		if err := rows.Scan(&runID, &stepID, &scanID, &s.ScanName, &s.RunStatus, &at, &s.StepName, &s.Capability, &s.Tool); err != nil {
			return nil, fmt.Errorf("scan story run: %w", err)
		}
		if s.RunID, err = shared.IDFromString(runID); err != nil {
			return nil, fmt.Errorf("story run id: %w", err)
		}
		s.StepRunID, s.ScanID = nullIDFromString(stepID), nullIDFromString(scanID)
		at = at.UTC()
		s.At = &at
		out = append(out, s)
	}
	return out, rows.Err()
}

// storyAssetRunsQuery reads, for asset $2 of tenant $1, the first run that
// derived it from a parent and the latest run that planned it as a target
// (ix_scan_run_targets_asset), each with its run and scan, tenant-bound.
const storyAssetRunsQuery = `
WITH picked AS (
	(SELECT 'discovered' AS role, t.run_id, t.relation, t.created_at
	 FROM scan_run_targets t
	 WHERE t.tenant_id = $1 AND t.asset_id = $2 AND t.origin = 'derived'
	 ORDER BY t.created_at, t.run_id
	 LIMIT 1)
	UNION ALL
	(SELECT 'scanned', t.run_id, NULL, t.created_at
	 FROM scan_run_targets t
	 WHERE t.tenant_id = $1 AND t.asset_id = $2 AND t.decision = 'planned'
	 ORDER BY t.created_at DESC, t.run_id
	 LIMIT 1)
)
SELECT p.role, r.id::text, r.scan_id::text, COALESCE(sc.name, ''), r.status, COALESCE(p.relation, ''), p.created_at
FROM picked p
JOIN scan_runs r ON r.tenant_id = $1 AND r.id = p.run_id
LEFT JOIN scans sc ON sc.tenant_id = $1 AND sc.id = r.scan_id`

// AssetRuns implements exploration.StoryStore.
func (r *StoryRepository) AssetRuns(ctx context.Context, tenantID, assetID shared.ID) (discovered, scanned *exploration.ScanStep, err error) {
	rows, err := r.db.QueryContext(ctx, storyAssetRunsQuery, tenantID.String(), assetID.String())
	if err != nil {
		return nil, nil, fmt.Errorf("query asset runs: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var (
			s      exploration.ScanStep
			runID  string
			scanID sql.NullString
			at     time.Time
		)
		if err := rows.Scan(&s.Role, &runID, &scanID, &s.ScanName, &s.RunStatus, &s.Relation, &at); err != nil {
			return nil, nil, fmt.Errorf("scan asset run: %w", err)
		}
		if s.RunID, err = shared.IDFromString(runID); err != nil {
			return nil, nil, fmt.Errorf("asset run id: %w", err)
		}
		s.ScanID = nullIDFromString(scanID)
		at = at.UTC()
		s.At = &at
		switch s.Role {
		case exploration.ScanDiscovered:
			discovered = &s
		case exploration.ScanScanned:
			scanned = &s
		}
	}
	return discovered, scanned, rows.Err()
}

// storyAssetReceiptQuery reads the upload receipt that created asset $2 of
// tenant $1 (assets.import_id), both rows tenant-bound.
const storyAssetReceiptQuery = `
SELECT ir.id::text, ir.source_kind, COALESCE(ir.tool_name, ''), ir.created_at
FROM assets a
JOIN ingest_receipts ir ON ir.tenant_id = $1 AND ir.id = a.import_id
WHERE a.tenant_id = $1 AND a.id = $2`

// AssetReceipt implements exploration.StoryStore.
func (r *StoryRepository) AssetReceipt(ctx context.Context, tenantID, assetID shared.ID) (*exploration.ReceiptRef, error) {
	var (
		ref exploration.ReceiptRef
		id  string
	)
	err := r.db.QueryRowContext(ctx, storyAssetReceiptQuery, tenantID.String(), assetID.String()).
		Scan(&id, &ref.SourceKind, &ref.Tool, &ref.At)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("query asset receipt: %w", err)
	}
	if ref.ID, err = shared.IDFromString(id); err != nil {
		return nil, fmt.Errorf("asset receipt id: %w", err)
	}
	ref.At = ref.At.UTC()
	return &ref, nil
}
