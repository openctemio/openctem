package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/app/easmdns"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// EASMDNSRepository backs the EASM DNS-only checks: which names are due, the
// per-name state, and resolving / reopening the exposures the checks own.
type EASMDNSRepository struct {
	db *DB
}

// NewEASMDNSRepository creates the repository.
func NewEASMDNSRepository(db *DB) *EASMDNSRepository { return &EASMDNSRepository{db: db} }

var _ easmdns.Store = (*EASMDNSRepository)(nil)

// assetTypesFor lists the asset types each check looks at.
func assetTypesFor(kind string) []string {
	if kind == easmdns.KindEmail {
		return []string{"domain"}
	}
	return []string{"domain", "subdomain"}
}

// DueTargets returns the tenant's active assets of the check's types whose
// attribution is not rejected and that were not checked since checkedBefore,
// never-checked first, then oldest check, up to limit.
func (r *EASMDNSRepository) DueTargets(ctx context.Context, tenantID shared.ID, kind string, checkedBefore time.Time, limit int) ([]easmdns.Target, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT a.id, a.name
		FROM assets a
		LEFT JOIN asset_attributions aa ON aa.asset_id = a.id
		LEFT JOIN easm_dns_check_state s ON s.asset_id = a.id AND s.check_kind = $2
		WHERE a.deleted_at IS NULL AND a.tenant_id = $1
		  AND a.asset_type = ANY($3)
		  AND a.status = 'active'
		  AND COALESCE(aa.state, 'confirmed') <> 'rejected'
		  AND (s.last_checked_at IS NULL OR s.last_checked_at < $4)
		ORDER BY s.last_checked_at ASC NULLS FIRST, a.name
		LIMIT $5`,
		tenantID.String(), kind, pq.Array(assetTypesFor(kind)), checkedBefore, limit)
	if err != nil {
		return nil, fmt.Errorf("list dns check targets: %w", err)
	}
	defer rows.Close()
	var out []easmdns.Target
	for rows.Next() {
		var id, name string
		if err := rows.Scan(&id, &name); err != nil {
			return nil, err
		}
		aid, err := shared.IDFromString(id)
		if err != nil {
			continue
		}
		out = append(out, easmdns.Target{AssetID: aid, Name: strings.ToLower(strings.TrimSuffix(name, "."))})
	}
	return out, rows.Err()
}

// SaveState records the last outcome of one check on one asset. The asset
// must be the tenant's: the insert selects it with the tenant id.
func (r *EASMDNSRepository) SaveState(ctx context.Context, tenantID, assetID shared.ID, kind, outcome, lastErr string, at time.Time) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO easm_dns_check_state (tenant_id, asset_id, check_kind, last_checked_at, last_outcome, last_error)
		SELECT a.tenant_id, a.id, $3, $4, $5, $6 FROM assets a WHERE a.id = $2 AND a.tenant_id = $1 AND a.deleted_at IS NULL
		ON CONFLICT (asset_id, check_kind) DO UPDATE SET
			last_checked_at = EXCLUDED.last_checked_at,
			last_outcome    = EXCLUDED.last_outcome,
			last_error      = EXCLUDED.last_error`,
		tenantID.String(), assetID.String(), kind, at, outcome, lastErr)
	if err != nil {
		return fmt.Errorf("save dns check state: %w", err)
	}
	return nil
}

// ResolveAuto resolves the tenant's ACTIVE exposures of this source with the
// given fingerprints and records the transition. Accepted, false-positive and
// already-resolved exposures are left alone.
func (r *EASMDNSRepository) ResolveAuto(ctx context.Context, tenantID shared.ID, source string, fingerprints []string, note string) (int, error) {
	return r.transition(ctx, `
		UPDATE exposure_events SET state = 'resolved', resolved_at = now(), resolved_by = NULL,
			resolution_notes = $4, updated_at = now()
		WHERE tenant_id = $1 AND source = $2 AND fingerprint = ANY($3) AND state = 'active'
		RETURNING id`, "active", "resolved", tenantID, source, fingerprints, note)
}

// ReopenAuto reopens exposures this check itself resolved (resolved_by NULL
// and its own note) that it finds again. A person's resolution or acceptance
// is never reopened.
func (r *EASMDNSRepository) ReopenAuto(ctx context.Context, tenantID shared.ID, source string, fingerprints []string, note string) (int, error) {
	return r.transition(ctx, `
		UPDATE exposure_events SET state = 'active', resolved_at = NULL, resolution_notes = '', updated_at = now()
		WHERE tenant_id = $1 AND source = $2 AND fingerprint = ANY($3)
		  AND state = 'resolved' AND resolved_by IS NULL AND resolution_notes = $4
		RETURNING id`, "resolved", "active", tenantID, source, fingerprints, note)
}

func (r *EASMDNSRepository) transition(ctx context.Context, update, from, to string, tenantID shared.ID, source string, fingerprints []string, note string) (int, error) {
	if len(fingerprints) == 0 {
		return 0, nil
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	ids, err := transitionedIDs(ctx, tx, update, tenantID, source, fingerprints, note)
	if err != nil {
		return 0, err
	}
	reason := "Reopened automatically: the DNS check finds the problem again."
	if to == "resolved" {
		reason = note
	}
	for _, id := range ids {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO exposure_state_history (id, exposure_event_id, previous_state, new_state, changed_by, reason, created_at)
			VALUES ($1, $2, $3, $4, NULL, $5, now())`,
			shared.NewID().String(), id, from, to, reason); err != nil {
			return 0, fmt.Errorf("record exposure transition: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return len(ids), nil
}

func transitionedIDs(ctx context.Context, tx *sql.Tx, update string, tenantID shared.ID, source string, fingerprints []string, note string) ([]string, error) {
	rows, err := tx.QueryContext(ctx, update, tenantID.String(), source, pq.Array(fingerprints), note)
	if err != nil {
		return nil, fmt.Errorf("transition exposures: %w", err)
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// easmDNSLockNamespace namespaces the per-tenant check lock ("EDNS").
const easmDNSLockNamespace int32 = 0x45444e53

// TryLockTenant serializes one check kind for one tenant across API
// replicas, on a dedicated connection (see CTMonitorStateRepository).
func (r *EASMDNSRepository) TryLockTenant(ctx context.Context, tenantID shared.ID, kind string) (func(), bool, error) {
	conn, err := r.db.Conn(ctx)
	if err != nil {
		return nil, false, fmt.Errorf("easm dns lock: %w", err)
	}
	key := tenantID.String() + ":" + kind
	var ok bool
	if err := conn.QueryRowContext(ctx, `SELECT pg_try_advisory_lock($1, hashtext($2))`, easmDNSLockNamespace, key).Scan(&ok); err != nil {
		_ = conn.Close()
		return nil, false, fmt.Errorf("easm dns lock: %w", err)
	}
	if !ok {
		_ = conn.Close()
		return nil, false, nil
	}
	return func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = conn.ExecContext(ctx, `SELECT pg_advisory_unlock($1, hashtext($2))`, easmDNSLockNamespace, key)
		_ = conn.Close()
	}, true, nil
}
