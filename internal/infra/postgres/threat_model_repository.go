package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/threatmodel"
	"github.com/openctemio/api/pkg/pagination"
)

// ThreatModelRepository implements threatmodel.Repository over PostgreSQL.
// Runtime reads/writes are tenant-scoped; catalog reads are global (seed data).
type ThreatModelRepository struct {
	db *DB
}

// NewThreatModelRepository creates a new ThreatModelRepository.
func NewThreatModelRepository(db *DB) *ThreatModelRepository {
	return &ThreatModelRepository{db: db}
}

var _ threatmodel.Repository = (*ThreatModelRepository)(nil)

const threatModelSelectCols = `id, tenant_id, scope_type, scope_ref_id, name,
	generated_at, input_hash, technique_dataset_version,
	threats_total, threats_open, threats_mitigated, threats_covered, coverage_pct,
	created_at, updated_at`

const threatSelectCols = `id, tenant_id, threat_model_id, attacker_profile_id,
	entry_point_asset_id, target_asset_id, hop_asset_id, hop_index, chain_fingerprint,
	technique_id, tactic, mitigation_id, status, status_reason, evidence_finding_id,
	score, created_at`

func (r *ThreatModelRepository) scanModel(scan func(dest ...any) error) (*threatmodel.ThreatModel, error) {
	var (
		id, tenantID              string
		scopeType                 string
		scopeRefID                sql.NullString
		name                      string
		generatedAt               time.Time
		inputHash, datasetVersion sql.NullString
		total, open, mit, cov     int
		coveragePct               float64
		createdAt, updatedAt      time.Time
	)
	if err := scan(&id, &tenantID, &scopeType, &scopeRefID, &name,
		&generatedAt, &inputHash, &datasetVersion,
		&total, &open, &mit, &cov, &coveragePct,
		&createdAt, &updatedAt); err != nil {
		return nil, err
	}
	tid, _ := shared.IDFromString(id)
	ttid, _ := shared.IDFromString(tenantID)
	return &threatmodel.ThreatModel{
		ID:                      tid,
		TenantID:                ttid,
		ScopeType:               threatmodel.ScopeType(scopeType),
		ScopeRefID:              parseNullID(scopeRefID),
		Name:                    name,
		GeneratedAt:             generatedAt,
		InputHash:               nullStringValue(inputHash),
		TechniqueDatasetVersion: nullStringValue(datasetVersion),
		ThreatsTotal:            total,
		ThreatsOpen:             open,
		ThreatsMitigated:        mit,
		ThreatsCovered:          cov,
		CoveragePct:             coveragePct,
		CreatedAt:               createdAt,
		UpdatedAt:               updatedAt,
	}, nil
}

func (r *ThreatModelRepository) scanThreat(scan func(dest ...any) error) (*threatmodel.ThreatModelThreat, error) {
	var (
		id, tenantID, modelID             string
		attackerID, entryID, targetID     sql.NullString
		hopID                             sql.NullString
		hopIndex                          int
		chainFP                           sql.NullString
		techniqueID, tactic, mitigationID sql.NullString
		status                            string
		statusReason                      sql.NullString
		evidenceID                        sql.NullString
		score                             float64
		createdAt                         time.Time
	)
	if err := scan(&id, &tenantID, &modelID, &attackerID,
		&entryID, &targetID, &hopID, &hopIndex, &chainFP,
		&techniqueID, &tactic, &mitigationID, &status, &statusReason, &evidenceID,
		&score, &createdAt); err != nil {
		return nil, err
	}
	tid, _ := shared.IDFromString(id)
	ttid, _ := shared.IDFromString(tenantID)
	mid, _ := shared.IDFromString(modelID)
	return &threatmodel.ThreatModelThreat{
		ID:                tid,
		TenantID:          ttid,
		ThreatModelID:     mid,
		AttackerProfileID: parseNullID(attackerID),
		EntryPointAssetID: parseNullID(entryID),
		TargetAssetID:     parseNullID(targetID),
		HopAssetID:        parseNullID(hopID),
		HopIndex:          hopIndex,
		ChainFingerprint:  nullStringValue(chainFP),
		TechniqueID:       nullStringValue(techniqueID),
		Tactic:            nullStringValue(tactic),
		MitigationID:      nullStringValue(mitigationID),
		Status:            threatmodel.ThreatStatus(status),
		StatusReason:      nullStringValue(statusReason),
		EvidenceFindingID: parseNullID(evidenceID),
		Score:             score,
		CreatedAt:         createdAt,
	}, nil
}

// Save creates or replaces a model and its threats in one transaction. The model
// is matched on its (tenant, scope_type, scope_ref_id) identity (NULL-safe); if a
// model already exists for the scope its id is reused and its threats are
// delete-and-inserted, so regeneration never drifts or leaves stale rows.
func (r *ThreatModelRepository) Save(ctx context.Context, model *threatmodel.ThreatModel, threats []*threatmodel.ThreatModelThreat) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Resolve any existing model for this scope (NULL-safe on scope_ref_id).
	var existingID string
	err = tx.QueryRowContext(ctx,
		`SELECT id FROM threat_models
		 WHERE tenant_id = $1 AND scope_type = $2 AND scope_ref_id IS NOT DISTINCT FROM $3`,
		model.TenantID.String(), model.ScopeType.String(), nullID(model.ScopeRefID),
	).Scan(&existingID)

	switch {
	case errors.Is(err, sql.ErrNoRows):
		if err := r.insertModel(ctx, tx, model); err != nil {
			return err
		}
	case err != nil:
		return fmt.Errorf("failed to resolve existing threat model: %w", err)
	default:
		reused, ierr := shared.IDFromString(existingID)
		if ierr != nil {
			return fmt.Errorf("failed to parse existing threat model id: %w", ierr)
		}
		model.ID = reused
		model.UpdatedAt = time.Now().UTC()
		if err := r.updateModel(ctx, tx, model); err != nil {
			return err
		}
		if _, derr := tx.ExecContext(ctx,
			`DELETE FROM threat_model_threats WHERE tenant_id = $1 AND threat_model_id = $2`,
			model.TenantID.String(), model.ID.String()); derr != nil {
			return fmt.Errorf("failed to clear existing threats: %w", derr)
		}
	}

	if err := r.insertThreats(ctx, tx, model, threats); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit threat model: %w", err)
	}
	return nil
}

func (r *ThreatModelRepository) insertModel(ctx context.Context, tx *sql.Tx, m *threatmodel.ThreatModel) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO threat_models
		(id, tenant_id, scope_type, scope_ref_id, name, generated_at, input_hash,
		 technique_dataset_version, threats_total, threats_open, threats_mitigated,
		 threats_covered, coverage_pct, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,
		m.ID.String(), m.TenantID.String(), m.ScopeType.String(), nullID(m.ScopeRefID),
		m.Name, m.GeneratedAt, nullString(m.InputHash), nullString(m.TechniqueDatasetVersion),
		m.ThreatsTotal, m.ThreatsOpen, m.ThreatsMitigated, m.ThreatsCovered, m.CoveragePct,
		m.CreatedAt, m.UpdatedAt)
	if err != nil {
		return fmt.Errorf("failed to insert threat model: %w", err)
	}
	return nil
}

func (r *ThreatModelRepository) updateModel(ctx context.Context, tx *sql.Tx, m *threatmodel.ThreatModel) error {
	_, err := tx.ExecContext(ctx, `UPDATE threat_models SET
		name = $3, generated_at = $4, input_hash = $5, technique_dataset_version = $6,
		threats_total = $7, threats_open = $8, threats_mitigated = $9,
		threats_covered = $10, coverage_pct = $11, updated_at = $12
		WHERE tenant_id = $1 AND id = $2`,
		m.TenantID.String(), m.ID.String(),
		m.Name, m.GeneratedAt, nullString(m.InputHash), nullString(m.TechniqueDatasetVersion),
		m.ThreatsTotal, m.ThreatsOpen, m.ThreatsMitigated, m.ThreatsCovered, m.CoveragePct,
		m.UpdatedAt)
	if err != nil {
		return fmt.Errorf("failed to update threat model: %w", err)
	}
	return nil
}

func (r *ThreatModelRepository) insertThreats(ctx context.Context, tx *sql.Tx, m *threatmodel.ThreatModel, threats []*threatmodel.ThreatModelThreat) error {
	const insertSQL = `INSERT INTO threat_model_threats
		(id, tenant_id, threat_model_id, attacker_profile_id, entry_point_asset_id,
		 target_asset_id, hop_asset_id, hop_index, chain_fingerprint, technique_id,
		 tactic, mitigation_id, status, status_reason, evidence_finding_id, score, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`
	for _, t := range threats {
		if t == nil {
			continue
		}
		// Re-tie every threat to the (possibly reused) model + tenant so the
		// caller never has to know whether the model was new or replaced.
		t.ThreatModelID = m.ID
		t.TenantID = m.TenantID
		if _, err := tx.ExecContext(ctx, insertSQL,
			t.ID.String(), t.TenantID.String(), t.ThreatModelID.String(),
			nullID(t.AttackerProfileID), nullID(t.EntryPointAssetID), nullID(t.TargetAssetID),
			nullID(t.HopAssetID), t.HopIndex, nullString(t.ChainFingerprint),
			nullString(t.TechniqueID), nullString(t.Tactic), nullString(t.MitigationID),
			string(t.Status), nullString(t.StatusReason), nullID(t.EvidenceFindingID),
			t.Score, t.CreatedAt); err != nil {
			return fmt.Errorf("failed to insert threat: %w", err)
		}
	}
	return nil
}

// GetByID returns a model by id, tenant-scoped.
func (r *ThreatModelRepository) GetByID(ctx context.Context, tenantID, id shared.ID) (*threatmodel.ThreatModel, error) {
	query := "SELECT " + threatModelSelectCols + " FROM threat_models WHERE tenant_id = $1 AND id = $2"
	m, err := r.scanModel(r.db.QueryRowContext(ctx, query, tenantID.String(), id.String()).Scan)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, threatmodel.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get threat model: %w", err)
	}
	return m, nil
}

// GetByScope returns the model for a (scopeType, scopeRefID) pair, tenant-scoped.
func (r *ThreatModelRepository) GetByScope(ctx context.Context, tenantID shared.ID, scopeType threatmodel.ScopeType, scopeRefID *shared.ID) (*threatmodel.ThreatModel, error) {
	query := "SELECT " + threatModelSelectCols + `
		FROM threat_models
		WHERE tenant_id = $1 AND scope_type = $2 AND scope_ref_id IS NOT DISTINCT FROM $3`
	m, err := r.scanModel(r.db.QueryRowContext(ctx, query,
		tenantID.String(), scopeType.String(), nullID(scopeRefID)).Scan)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, threatmodel.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get threat model by scope: %w", err)
	}
	return m, nil
}

// ListModels returns models for a tenant, filtered and paginated, plus the total.
func (r *ThreatModelRepository) ListModels(ctx context.Context, tenantID shared.ID, filter threatmodel.ModelFilter, page pagination.Pagination) ([]*threatmodel.ThreatModel, int, error) {
	where := "WHERE tenant_id = $1"
	args := []any{tenantID.String()}
	if filter.ScopeType != "" {
		args = append(args, filter.ScopeType.String())
		where += fmt.Sprintf(" AND scope_type = $%d", len(args))
	}
	if filter.ScopeRefID != nil {
		args = append(args, filter.ScopeRefID.String())
		where += fmt.Sprintf(" AND scope_ref_id = $%d", len(args))
	}

	var total int
	if err := r.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM threat_models "+where, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("failed to count threat models: %w", err)
	}

	args = append(args, page.Limit(), page.Offset())
	query := "SELECT " + threatModelSelectCols + " FROM threat_models " + where +
		fmt.Sprintf(" ORDER BY generated_at DESC LIMIT $%d OFFSET $%d", len(args)-1, len(args))
	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list threat models: %w", err)
	}
	defer func() { _ = rows.Close() }()

	models := make([]*threatmodel.ThreatModel, 0, page.Limit())
	for rows.Next() {
		m, serr := r.scanModel(rows.Scan)
		if serr != nil {
			return nil, 0, fmt.Errorf("failed to scan threat model: %w", serr)
		}
		models = append(models, m)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("error iterating threat models: %w", err)
	}
	return models, total, nil
}

// ListThreats returns the threats for a model, tenant-scoped and filtered.
func (r *ThreatModelRepository) ListThreats(ctx context.Context, tenantID, modelID shared.ID, filter threatmodel.ThreatFilter) ([]*threatmodel.ThreatModelThreat, error) {
	where := "WHERE tenant_id = $1 AND threat_model_id = $2"
	args := []any{tenantID.String(), modelID.String()}
	if filter.Status != "" {
		args = append(args, filter.Status.String())
		where += fmt.Sprintf(" AND status = $%d", len(args))
	}
	if filter.AttackerProfileID != nil {
		args = append(args, filter.AttackerProfileID.String())
		where += fmt.Sprintf(" AND attacker_profile_id = $%d", len(args))
	}
	if filter.Tactic != "" {
		args = append(args, filter.Tactic)
		where += fmt.Sprintf(" AND tactic = $%d", len(args))
	}
	if filter.TechniqueID != "" {
		args = append(args, filter.TechniqueID)
		where += fmt.Sprintf(" AND technique_id = $%d", len(args))
	}

	query := "SELECT " + threatSelectCols + " FROM threat_model_threats " + where +
		" ORDER BY hop_index ASC, score DESC"
	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list threats: %w", err)
	}
	defer func() { _ = rows.Close() }()

	threats := make([]*threatmodel.ThreatModelThreat, 0)
	for rows.Next() {
		t, serr := r.scanThreat(rows.Scan)
		if serr != nil {
			return nil, fmt.Errorf("failed to scan threat: %w", serr)
		}
		threats = append(threats, t)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating threats: %w", err)
	}
	return threats, nil
}

// AssetsOnOpenThreatPaths returns the set of asset IDs (entry points, targets,
// and hops) that sit on an OPEN threat with score >= minScore across the
// tenant's current threat models. Feeds the priority classifier's
// ThreatModelOracle. Tenant-scoped and served by idx_tmt_status(tenant_id,
// status) — a single indexed query, no N+1. Because Save() replaces a scope's
// threats wholesale (delete-and-insert), every row is current, so aggregating
// across the tenant's models yields its latest picture.
func (r *ThreatModelRepository) AssetsOnOpenThreatPaths(ctx context.Context, tenantID shared.ID, minScore float64) (map[string]bool, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT entry_point_asset_id, target_asset_id, hop_asset_id
		   FROM threat_model_threats
		  WHERE tenant_id = $1 AND status = $2 AND score >= $3`,
		tenantID.String(), string(threatmodel.StatusOpen), minScore)
	if err != nil {
		return nil, fmt.Errorf("failed to list open threat-path assets: %w", err)
	}
	defer func() { _ = rows.Close() }()

	set := make(map[string]bool)
	for rows.Next() {
		var entryID, targetID, hopID sql.NullString
		if err := rows.Scan(&entryID, &targetID, &hopID); err != nil {
			return nil, fmt.Errorf("failed to scan open threat-path asset: %w", err)
		}
		for _, v := range []sql.NullString{entryID, targetID, hopID} {
			if v.Valid && v.String != "" {
				set[v.String] = true
			}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating open threat-path assets: %w", err)
	}
	return set, nil
}

// Delete removes a model (and its threats via ON DELETE CASCADE), tenant-scoped.
func (r *ThreatModelRepository) Delete(ctx context.Context, tenantID, id shared.ID) error {
	_, err := r.db.ExecContext(ctx,
		"DELETE FROM threat_models WHERE tenant_id = $1 AND id = $2",
		tenantID.String(), id.String())
	if err != nil {
		return fmt.Errorf("failed to delete threat model: %w", err)
	}
	return nil
}

// ListTechniqueMitigations returns the global technique→mitigation catalog.
func (r *ThreatModelRepository) ListTechniqueMitigations(ctx context.Context, datasetVersion string) ([]threatmodel.TechniqueMitigation, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT technique_id, technique_name, tactic,
		mitigation_id, mitigation_name, mitigation_summary, dataset_version
		FROM attack_technique_mitigations WHERE dataset_version = $1
		ORDER BY technique_id, mitigation_id`, datasetVersion)
	if err != nil {
		return nil, fmt.Errorf("failed to list technique mitigations: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := make([]threatmodel.TechniqueMitigation, 0)
	for rows.Next() {
		var m threatmodel.TechniqueMitigation
		var summary sql.NullString
		if err := rows.Scan(&m.TechniqueID, &m.TechniqueName, &m.Tactic,
			&m.MitigationID, &m.MitigationName, &summary, &m.DatasetVersion); err != nil {
			return nil, fmt.Errorf("failed to scan technique mitigation: %w", err)
		}
		m.MitigationSummary = nullStringValue(summary)
		out = append(out, m)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating technique mitigations: %w", err)
	}
	return out, nil
}

// ListApplicability returns the global technique-applicability catalog.
func (r *ThreatModelRepository) ListApplicability(ctx context.Context, datasetVersion string) ([]threatmodel.TechniqueApplicability, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT technique_id, asset_type, edge_type,
		min_network, min_credential, requires_persistence, dataset_version
		FROM technique_applicability WHERE dataset_version = $1
		ORDER BY technique_id, asset_type`, datasetVersion)
	if err != nil {
		return nil, fmt.Errorf("failed to list technique applicability: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := make([]threatmodel.TechniqueApplicability, 0)
	for rows.Next() {
		var a threatmodel.TechniqueApplicability
		var edge, minNet, minCred sql.NullString
		if err := rows.Scan(&a.TechniqueID, &a.AssetType, &edge,
			&minNet, &minCred, &a.RequiresPersistence, &a.DatasetVersion); err != nil {
			return nil, fmt.Errorf("failed to scan technique applicability: %w", err)
		}
		a.EdgeType = nullStringValue(edge)
		a.MinNetwork = nullStringValue(minNet)
		a.MinCredential = nullStringValue(minCred)
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating technique applicability: %w", err)
	}
	return out, nil
}
