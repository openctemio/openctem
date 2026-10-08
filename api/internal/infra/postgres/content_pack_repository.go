package postgres

// Content packs (docs/rfcs/RFC-061-content-packs.md; migration 001380).
// Every statement is tenant-scoped, and a pack's blob is the same tenant's
// by the composite foreign key (tenant_id, digest).

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/contentpack"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ContentPackRepository implements contentpack.Repository.
type ContentPackRepository struct {
	db *DB
}

// NewContentPackRepository creates a ContentPackRepository.
func NewContentPackRepository(db *DB) *ContentPackRepository {
	return &ContentPackRepository{db: db}
}

var _ contentpack.Repository = (*ContentPackRepository)(nil)

// GetBlob returns the tenant's blob of digest.
func (r *ContentPackRepository) GetBlob(ctx context.Context, tenantID shared.ID, digest string) (*contentpack.Blob, error) {
	b := &contentpack.Blob{TenantID: tenantID, Digest: digest}
	err := r.db.QueryRowContext(ctx, `
		SELECT size_bytes, file_count, storage_key, created_at
		FROM content_pack_blobs WHERE tenant_id = $1 AND digest = $2`,
		tenantID.String(), digest).Scan(&b.SizeBytes, &b.FileCount, &b.StorageKey, &b.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, contentpack.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get content pack blob: %w", err)
	}
	return b, nil
}

// CreateBlob stores b unless the tenant already has its digest.
func (r *ContentPackRepository) CreateBlob(ctx context.Context, b *contentpack.Blob) (bool, error) {
	res, err := r.db.ExecContext(ctx, `
		INSERT INTO content_pack_blobs (tenant_id, digest, size_bytes, file_count, storage_key, created_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (tenant_id, digest) DO NOTHING`,
		b.TenantID.String(), b.Digest, b.SizeBytes, b.FileCount, b.StorageKey, b.CreatedAt)
	if err != nil {
		return false, fmt.Errorf("create content pack blob: %w", err)
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// Create stores a pack.
func (r *ContentPackRepository) Create(ctx context.Context, p *contentpack.Pack) error {
	lint, err := json.Marshal(p.Lint)
	if err != nil {
		return fmt.Errorf("encode lint report: %w", err)
	}
	_, err = r.db.ExecContext(ctx, `
		INSERT INTO content_packs (id, tenant_id, name, version, kind, digest, tier, status, source,
			source_ref, lint, signature, created_by, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`,
		p.ID.String(), p.TenantID.String(), p.Name, p.Version, p.Kind, p.Digest, string(p.Tier),
		string(p.Status), string(p.Source), nullString(p.SourceRef), lint, p.Signature,
		nullIDPtr(p.CreatedBy), p.CreatedAt)
	if err != nil {
		if isUniqueViolation(err) {
			return contentpack.ErrExists
		}
		return fmt.Errorf("create content pack: %w", err)
	}
	return nil
}

const contentPackSelect = `
	SELECT p.id, p.tenant_id, p.name, p.version, p.kind, p.digest, b.size_bytes, b.file_count,
		p.tier, p.status, p.source, p.source_ref, p.lint, p.signature, p.created_by, p.created_at,
		p.revoked_at, p.revoked_by, p.revoke_reason
	FROM content_packs p
	JOIN content_pack_blobs b ON b.tenant_id = p.tenant_id AND b.digest = p.digest`

func scanContentPack(row interface{ Scan(...any) error }) (*contentpack.Pack, error) {
	var (
		p                    contentpack.Pack
		id, tenantID         string
		tier, status, source string
		sourceRef, reason    sql.NullString
		createdBy, revokedBy sql.NullString
		revokedAt            sql.NullTime
		lint                 []byte
	)
	if err := row.Scan(&id, &tenantID, &p.Name, &p.Version, &p.Kind, &p.Digest, &p.SizeBytes, &p.FileCount,
		&tier, &status, &source, &sourceRef, &lint, &p.Signature, &createdBy, &p.CreatedAt,
		&revokedAt, &revokedBy, &reason); err != nil {
		return nil, err
	}
	p.ID, _ = shared.IDFromString(id)
	p.TenantID, _ = shared.IDFromString(tenantID)
	p.Tier, p.Status, p.Source = contentpack.Tier(tier), contentpack.Status(status), contentpack.Source(source)
	p.SourceRef, p.RevokeReason = sourceRef.String, reason.String
	if err := json.Unmarshal(lint, &p.Lint); err != nil {
		return nil, fmt.Errorf("decode lint report: %w", err)
	}
	if createdBy.Valid {
		if cid, err := shared.IDFromString(createdBy.String); err == nil {
			p.CreatedBy = &cid
		}
	}
	if revokedBy.Valid {
		if rid, err := shared.IDFromString(revokedBy.String); err == nil {
			p.RevokedBy = &rid
		}
	}
	if revokedAt.Valid {
		t := revokedAt.Time
		p.RevokedAt = &t
	}
	return &p, nil
}

// GetByID returns a pack of the tenant.
func (r *ContentPackRepository) GetByID(ctx context.Context, tenantID, id shared.ID) (*contentpack.Pack, error) {
	p, err := scanContentPack(r.db.QueryRowContext(ctx, contentPackSelect+` WHERE p.tenant_id = $1 AND p.id = $2`,
		tenantID.String(), id.String()))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, contentpack.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get content pack: %w", err)
	}
	return p, nil
}

// List returns a page of the tenant's packs, newest first, and the total.
func (r *ContentPackRepository) List(ctx context.Context, tenantID shared.ID, f contentpack.Filter, limit, offset int) ([]*contentpack.Pack, int, error) {
	where := ` WHERE p.tenant_id = $1
		AND ($2::text = '' OR p.kind = $2)
		AND ($3::text = '' OR p.name = $3)
		AND ($4::text = '' OR p.status = $4)`
	args := []any{tenantID.String(), f.Kind, f.Name, string(f.Status)}
	var total int
	if err := r.db.QueryRowContext(ctx, `SELECT count(*) FROM content_packs p`+where, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count content packs: %w", err)
	}
	rows, err := r.db.QueryContext(ctx, contentPackSelect+where+` ORDER BY p.created_at DESC, p.id DESC LIMIT $5 OFFSET $6`,
		append(args, limit, offset)...)
	if err != nil {
		return nil, 0, fmt.Errorf("list content packs: %w", err)
	}
	defer rows.Close()
	out := make([]*contentpack.Pack, 0, limit)
	for rows.Next() {
		p, err := scanContentPack(rows)
		if err != nil {
			return nil, 0, fmt.Errorf("list content packs: %w", err)
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("list content packs: %w", err)
	}
	return out, total, nil
}

// Revoke revokes an active pack of the tenant.
func (r *ContentPackRepository) Revoke(ctx context.Context, tenantID, id shared.ID, by *shared.ID, reason string, at time.Time) error {
	res, err := r.db.ExecContext(ctx, `
		UPDATE content_packs SET status = 'revoked', revoked_at = $3, revoked_by = $4, revoke_reason = $5
		WHERE tenant_id = $1 AND id = $2 AND status = 'active'`,
		tenantID.String(), id.String(), at, nullIDPtr(by), nullString(reason))
	if err != nil {
		return fmt.Errorf("revoke content pack: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 1 {
		return nil
	}
	if _, err := r.GetByID(ctx, tenantID, id); err != nil {
		return err
	}
	return contentpack.ErrNotActive
}

// Usage is the tenant's pack count and stored bytes.
func (r *ContentPackRepository) Usage(ctx context.Context, tenantID shared.ID) (int, int64, error) {
	var (
		packs int
		bytes int64
	)
	if err := r.db.QueryRowContext(ctx, `
		SELECT (SELECT count(*) FROM content_packs WHERE tenant_id = $1),
		       (SELECT COALESCE(sum(size_bytes), 0) FROM content_pack_blobs WHERE tenant_id = $1)`,
		tenantID.String()).Scan(&packs, &bytes); err != nil {
		return 0, 0, fmt.Errorf("content pack usage: %w", err)
	}
	return packs, bytes, nil
}
