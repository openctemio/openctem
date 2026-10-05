package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/app/easm"
	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// tenant_scanned evidence for the assets of a tenant's own scans (RFC-036
// O8). Every statement is tenant-scoped.

var _ easm.ScanEvidenceStore = (*AttributionRepository)(nil)

// UpsertEvidenceBulk records ev for every asset in assetIDs that is the
// tenant's and not deleted, in one statement. An existing (asset, rule,
// source) row keeps its first_observed_at and gets the new datum.
func (r *AttributionRepository) UpsertEvidenceBulk(ctx context.Context, tenantID shared.ID, assetIDs []string, ev attribution.Evidence) error {
	if len(assetIDs) == 0 {
		return nil
	}
	observed := []byte("{}")
	if ev.Observed != nil {
		b, err := json.Marshal(ev.Observed)
		if err != nil {
			return fmt.Errorf("encode evidence: %w", err)
		}
		observed = b
	}
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO easm_evidence (id, tenant_id, asset_id, rule, technique, source, weight, observed)
		SELECT gen_random_uuid(), a.tenant_id, a.id, $3, $4, $5, $6, $7
		FROM assets a WHERE a.id = ANY($2::uuid[]) AND a.tenant_id = $1 AND a.deleted_at IS NULL
		ON CONFLICT (asset_id, rule, source) DO UPDATE SET
			technique        = EXCLUDED.technique,
			weight           = EXCLUDED.weight,
			observed         = EXCLUDED.observed,
			last_observed_at = now()
		WHERE easm_evidence.tenant_id = EXCLUDED.tenant_id`,
		tenantID.String(), pq.Array(assetIDs), string(ev.Rule), ev.Technique, ev.Source, ev.Weight, observed)
	if err != nil {
		return fmt.Errorf("upsert evidence: %w", err)
	}
	return nil
}

// ScanRunOf returns the pipeline run and scan of a step run in the tenant.
// An unknown step run, or one of another tenant, yields empty strings.
func (r *AttributionRepository) ScanRunOf(ctx context.Context, tenantID, stepRunID shared.ID) (string, string, error) {
	var runID string
	var scanID sql.NullString
	err := r.db.QueryRowContext(ctx, `
		SELECT pr.id, pr.scan_id FROM step_runs sr
		JOIN pipeline_runs pr ON pr.id = sr.pipeline_run_id
		WHERE sr.id = $2 AND pr.tenant_id = $1`, tenantID.String(), stepRunID.String()).Scan(&runID, &scanID)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", nil
	}
	if err != nil {
		return "", "", fmt.Errorf("resolve scan run: %w", err)
	}
	return runID, scanID.String, nil
}
