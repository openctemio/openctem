package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/app/certmonitor"
	"github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// AttributionRepository stores asset attribution (asset_attributions) and its
// evidence (easm_evidence), RFC-036 §6.4. Every query is tenant-scoped.
type AttributionRepository struct {
	db *DB
}

var (
	_ certmonitor.AttributionStore = (*AttributionRepository)(nil)
	_ scan.AttributionGate         = (*AttributionRepository)(nil)
)

// NewAttributionRepository creates the repository.
func NewAttributionRepository(db *DB) *AttributionRepository {
	return &AttributionRepository{db: db}
}

// AttributionView is an asset's stored attribution with its evidence.
type AttributionView struct {
	Record    attribution.Record
	DecidedAt *time.Time
	UpdatedAt time.Time
	Evidence  []EvidenceView
}

// EvidenceView is one stored evidence row.
type EvidenceView struct {
	Rule            attribution.Rule
	Technique       string
	Source          string
	Weight          float64
	Observed        map[string]any
	FirstObservedAt time.Time
	LastObservedAt  time.Time
}

// UpsertEvidence records evidence rows. A row that already exists for (asset,
// rule, source) keeps its first_observed_at and gets the new datum and
// last_observed_at. The asset must belong to the tenant: the insert selects
// it from assets with the tenant id, so a foreign asset id writes nothing.
func (r *AttributionRepository) UpsertEvidence(ctx context.Context, tenantID shared.ID, ev []attribution.Evidence) error {
	for _, e := range ev {
		observed, err := json.Marshal(e.Observed)
		if err != nil {
			return fmt.Errorf("encode evidence: %w", err)
		}
		if e.Observed == nil {
			observed = []byte("{}")
		}
		_, err = r.db.ExecContext(ctx, `
			INSERT INTO easm_evidence (id, tenant_id, asset_id, rule, technique, source, weight, observed)
			SELECT $1, a.tenant_id, a.id, $4, $5, $6, $7, $8
			FROM assets a WHERE a.id = $3 AND a.tenant_id = $2 AND a.deleted_at IS NULL
			ON CONFLICT (asset_id, rule, source) DO UPDATE SET
				technique        = EXCLUDED.technique,
				weight           = EXCLUDED.weight,
				observed         = EXCLUDED.observed,
				last_observed_at = now()`,
			shared.NewID().String(), tenantID.String(), e.AssetID, string(e.Rule), e.Technique, e.Source, e.Weight, observed)
		if err != nil {
			return fmt.Errorf("upsert evidence: %w", err)
		}
	}
	return nil
}

// FiredRules returns, per asset, the distinct rules of its stored evidence.
func (r *AttributionRepository) FiredRules(ctx context.Context, tenantID shared.ID, assetIDs []string) (map[string][]attribution.Rule, error) {
	out := map[string][]attribution.Rule{}
	if len(assetIDs) == 0 {
		return out, nil
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT DISTINCT asset_id, rule FROM easm_evidence
		WHERE tenant_id = $1 AND asset_id = ANY($2::uuid[])`, tenantID.String(), pq.Array(assetIDs))
	if err != nil {
		return nil, fmt.Errorf("list fired rules: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id, rule string
		if err := rows.Scan(&id, &rule); err != nil {
			return nil, err
		}
		out[id] = append(out[id], attribution.Rule(rule))
	}
	return out, rows.Err()
}

// Records returns the stored attribution of the given assets; an asset with
// no row is absent from the map (a legacy, confirmed asset).
func (r *AttributionRepository) Records(ctx context.Context, tenantID shared.ID, assetIDs []string) (map[string]attribution.Record, error) {
	out := map[string]attribution.Record{}
	if len(assetIDs) == 0 {
		return out, nil
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT asset_id, state, confidence, reason, decided_at IS NOT NULL
		FROM asset_attributions
		WHERE tenant_id = $1 AND asset_id = ANY($2::uuid[])`, tenantID.String(), pq.Array(assetIDs))
	if err != nil {
		return nil, fmt.Errorf("list attributions: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var (
			id, state, reason string
			rec               attribution.Record
		)
		if err := rows.Scan(&id, &state, &rec.Confidence, &reason, &rec.HumanDecided); err != nil {
			return nil, err
		}
		rec.State, rec.Reason = attribution.State(state), attribution.Rule(reason)
		out[id] = rec
	}
	return out, rows.Err()
}

// SaveAutomatic stores an automatic decision. It never overwrites a human
// decision (decided_at set): the update is skipped for such rows. The caller
// computes the decision with attribution.Merge so automation only raises.
func (r *AttributionRepository) SaveAutomatic(ctx context.Context, tenantID shared.ID, assetID string, d attribution.Decision) error {
	if !d.State.Valid() {
		return fmt.Errorf("%w: invalid attribution state %q", shared.ErrValidation, d.State)
	}
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO asset_attributions (asset_id, tenant_id, state, confidence, reason)
		SELECT a.id, a.tenant_id, $3, $4, $5
		FROM assets a WHERE a.id = $1 AND a.tenant_id = $2 AND a.deleted_at IS NULL
		ON CONFLICT (asset_id) DO UPDATE SET
			state      = EXCLUDED.state,
			confidence = EXCLUDED.confidence,
			reason     = EXCLUDED.reason,
			updated_at = now()
		WHERE asset_attributions.decided_at IS NULL`,
		assetID, tenantID.String(), string(d.State), d.Confidence, string(d.Reason))
	if err != nil {
		return fmt.Errorf("save attribution: %w", err)
	}
	return nil
}

// Get returns one asset's attribution and evidence. found=false means the
// asset has no record (legacy, confirmed) — evidence may still exist.
func (r *AttributionRepository) Get(ctx context.Context, tenantID shared.ID, assetID string) (*AttributionView, bool, error) {
	view := &AttributionView{}
	var (
		state, reason string
		decidedAt     sql.NullTime
	)
	err := r.db.QueryRowContext(ctx, `
		SELECT state, confidence, reason, decided_at, updated_at
		FROM asset_attributions WHERE tenant_id = $1 AND asset_id = $2`,
		tenantID.String(), assetID).Scan(&state, &view.Record.Confidence, &reason, &decidedAt, &view.UpdatedAt)
	found := true
	switch {
	case errors.Is(err, sql.ErrNoRows):
		found = false
	case err != nil:
		return nil, false, fmt.Errorf("get attribution: %w", err)
	default:
		view.Record.State, view.Record.Reason = attribution.State(state), attribution.Rule(reason)
		view.Record.HumanDecided = decidedAt.Valid
		view.DecidedAt = nullTimeValue(decidedAt)
	}

	rows, err := r.db.QueryContext(ctx, `
		SELECT rule, technique, source, weight, observed, first_observed_at, last_observed_at
		FROM easm_evidence WHERE tenant_id = $1 AND asset_id = $2
		ORDER BY weight DESC, first_observed_at`, tenantID.String(), assetID)
	if err != nil {
		return nil, false, fmt.Errorf("list evidence: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var (
			ev       EvidenceView
			rule     string
			observed []byte
		)
		if err := rows.Scan(&rule, &ev.Technique, &ev.Source, &ev.Weight, &observed, &ev.FirstObservedAt, &ev.LastObservedAt); err != nil {
			return nil, false, err
		}
		ev.Rule = attribution.Rule(rule)
		_ = json.Unmarshal(observed, &ev.Observed)
		view.Evidence = append(view.Evidence, ev)
	}
	return view, found, rows.Err()
}

// ActiveCheckBlocked returns the subset of the given assets whose
// attribution forbids active checks (any stored state other than confirmed).
// Assets without a record are legacy and allowed.
func (r *AttributionRepository) ActiveCheckBlocked(ctx context.Context, tenantID shared.ID, assetIDs []string) (map[string]attribution.State, error) {
	out := map[string]attribution.State{}
	if len(assetIDs) == 0 {
		return out, nil
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT asset_id, state FROM asset_attributions
		WHERE tenant_id = $1 AND asset_id = ANY($2::uuid[]) AND state <> 'confirmed'`,
		tenantID.String(), pq.Array(assetIDs))
	if err != nil {
		return nil, fmt.Errorf("list blocked attributions: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id, state string
		if err := rows.Scan(&id, &state); err != nil {
			return nil, err
		}
		out[id] = attribution.State(state)
	}
	return out, rows.Err()
}

// SaveDecision records a person's decision on an asset's attribution. From
// then on automation leaves the state alone (SaveAutomatic skips rows with
// decided_at). found=false when the asset is not the tenant's.
func (r *AttributionRepository) SaveDecision(ctx context.Context, tenantID shared.ID, assetID string, state attribution.State, decidedBy string) (bool, error) {
	if !state.Valid() {
		return false, fmt.Errorf("%w: invalid attribution state %q", shared.ErrValidation, state)
	}
	var by any
	if id, err := shared.IDFromString(decidedBy); err == nil {
		by = id.String()
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("save attribution decision: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var got string
	err = tx.QueryRowContext(ctx, `
		INSERT INTO asset_attributions (asset_id, tenant_id, state, confidence, reason, decided_by, decided_at)
		SELECT a.id, a.tenant_id, $3, 0, '', (SELECT u.id FROM users u WHERE u.id = $4::uuid), now()
		FROM assets a WHERE a.id = $1 AND a.tenant_id = $2 AND a.deleted_at IS NULL
		ON CONFLICT (asset_id) DO UPDATE SET
			state      = EXCLUDED.state,
			decided_by = EXCLUDED.decided_by,
			decided_at = now(),
			updated_at = now()
		RETURNING asset_id`,
		assetID, tenantID.String(), string(state), by).Scan(&got)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("save attribution decision: %w", err)
	}
	if err := syncTombstones(ctx, tx, tenantID, []string{got}, state, by); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("save attribution decision: %w", err)
	}
	return true, nil
}
