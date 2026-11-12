package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/toolsource"
)

// ToolSourceKeyRepository implements toolsource.Repository on the
// tool_source_keys table. Every query is scoped by tenant_id; the key column
// holds ciphertext only.
type ToolSourceKeyRepository struct {
	db *DB
}

// NewToolSourceKeyRepository creates the repository.
func NewToolSourceKeyRepository(db *DB) *ToolSourceKeyRepository {
	return &ToolSourceKeyRepository{db: db}
}

var _ toolsource.Repository = (*ToolSourceKeyRepository)(nil)

const toolSourceKeyColumns = `k.tenant_id::text, k.source, k.key_enc, k.key_last4, k.enabled, k.created_by::text, k.created_at,
	k.updated_by::text, COALESCE(NULLIF(u.name, ''), u.email, ''), k.updated_at, k.last_used_at`

const toolSourceKeyFrom = ` FROM tool_source_keys k LEFT JOIN users u ON u.id = k.updated_by`

func scanToolSourceKey(row interface{ Scan(...any) error }) (toolsource.Key, error) {
	var (
		k                toolsource.Key
		tenant           string
		createdBy, updBy sql.NullString
		lastUsed         sql.NullTime
	)
	if err := row.Scan(&tenant, &k.Source, &k.KeyEnc, &k.Last4, &k.Enabled, &createdBy, &k.CreatedAt,
		&updBy, &k.UpdatedByName, &k.UpdatedAt, &lastUsed); err != nil {
		return k, err
	}
	tid, err := shared.IDFromString(tenant)
	if err != nil {
		return k, fmt.Errorf("tool source key tenant: %w", err)
	}
	k.TenantID = tid
	k.CreatedBy = optionalID(createdBy)
	k.UpdatedBy = optionalID(updBy)
	if lastUsed.Valid {
		t := lastUsed.Time
		k.LastUsedAt = &t
	}
	return k, nil
}

// List returns the tenant's keys, ordered by source.
func (r *ToolSourceKeyRepository) List(ctx context.Context, tenantID shared.ID) ([]toolsource.Key, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT `+toolSourceKeyColumns+toolSourceKeyFrom+
		` WHERE k.tenant_id = $1 ORDER BY k.source`, tenantID.String())
	if err != nil {
		return nil, fmt.Errorf("list tool source keys: %w", err)
	}
	defer rows.Close()
	var out []toolsource.Key
	for rows.Next() {
		k, err := scanToolSourceKey(rows)
		if err != nil {
			return nil, fmt.Errorf("scan tool source key: %w", err)
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// Get returns one key of the tenant.
func (r *ToolSourceKeyRepository) Get(ctx context.Context, tenantID shared.ID, source string) (*toolsource.Key, error) {
	k, err := scanToolSourceKey(r.db.QueryRowContext(ctx, `SELECT `+toolSourceKeyColumns+toolSourceKeyFrom+
		` WHERE k.tenant_id = $1 AND k.source = $2`, tenantID.String(), source))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, shared.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("read tool source key: %w", err)
	}
	return &k, nil
}

// Upsert stores or replaces a key.
func (r *ToolSourceKeyRepository) Upsert(ctx context.Context, k *toolsource.Key) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO tool_source_keys (tenant_id, source, key_enc, key_last4, enabled, created_by, created_at, updated_by, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $6, $7)
		ON CONFLICT (tenant_id, source) DO UPDATE
		   SET key_enc = EXCLUDED.key_enc, key_last4 = EXCLUDED.key_last4,
		       updated_by = EXCLUDED.updated_by, updated_at = EXCLUDED.updated_at`,
		k.TenantID.String(), k.Source, k.KeyEnc, k.Last4, k.Enabled, nullableID(k.UpdatedBy), k.UpdatedAt)
	if err != nil {
		return fmt.Errorf("store tool source key: %w", err)
	}
	return nil
}

// SetEnabled switches a key on or off.
func (r *ToolSourceKeyRepository) SetEnabled(ctx context.Context, tenantID shared.ID, source string, enabled bool, by *shared.ID) error {
	res, err := r.db.ExecContext(ctx, `UPDATE tool_source_keys SET enabled = $3, updated_by = $4, updated_at = now()
		WHERE tenant_id = $1 AND source = $2`, tenantID.String(), source, enabled, nullableID(by))
	if err != nil {
		return fmt.Errorf("switch tool source key: %w", err)
	}
	return oneRowAffected(res, shared.ErrNotFound)
}

// Delete removes a key.
func (r *ToolSourceKeyRepository) Delete(ctx context.Context, tenantID shared.ID, source string) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM tool_source_keys WHERE tenant_id = $1 AND source = $2`, tenantID.String(), source)
	if err != nil {
		return fmt.Errorf("delete tool source key: %w", err)
	}
	return oneRowAffected(res, shared.ErrNotFound)
}

// Enabled returns the tenant's enabled keys among sources.
func (r *ToolSourceKeyRepository) Enabled(ctx context.Context, tenantID shared.ID, sources []string) ([]toolsource.Key, error) {
	if len(sources) == 0 {
		return nil, nil
	}
	rows, err := r.db.QueryContext(ctx, `SELECT `+toolSourceKeyColumns+toolSourceKeyFrom+
		` WHERE k.tenant_id = $1 AND k.enabled AND k.source = ANY($2) ORDER BY k.source`, tenantID.String(), pq.Array(sources))
	if err != nil {
		return nil, fmt.Errorf("read enabled tool source keys: %w", err)
	}
	defer rows.Close()
	var out []toolsource.Key
	for rows.Next() {
		k, err := scanToolSourceKey(rows)
		if err != nil {
			return nil, fmt.Errorf("scan tool source key: %w", err)
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// MarkUsed records a delivery of the tenant's keys of sources.
func (r *ToolSourceKeyRepository) MarkUsed(ctx context.Context, tenantID shared.ID, sources []string, at time.Time) error {
	if len(sources) == 0 {
		return nil
	}
	_, err := r.db.ExecContext(ctx, `UPDATE tool_source_keys SET last_used_at = $3 WHERE tenant_id = $1 AND source = ANY($2)`,
		tenantID.String(), pq.Array(sources), at)
	if err != nil {
		return fmt.Errorf("mark tool source keys used: %w", err)
	}
	return nil
}
