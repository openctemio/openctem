package postgres

// Platform content packs (docs/rfcs/RFC-061-content-packs.md; migration
// 001387): packs, blobs and channels the platform operator manages. Apart
// from the tenant tables on purpose: no tenant statement touches them.

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

// PlatformContentPackRepository implements contentpack.PlatformRepository.
type PlatformContentPackRepository struct {
	db *DB
}

// NewPlatformContentPackRepository creates a PlatformContentPackRepository.
func NewPlatformContentPackRepository(db *DB) *PlatformContentPackRepository {
	return &PlatformContentPackRepository{db: db}
}

var _ contentpack.PlatformRepository = (*PlatformContentPackRepository)(nil)

// GetBlob returns the blob of digest.
func (r *PlatformContentPackRepository) GetBlob(ctx context.Context, digest string) (*contentpack.Blob, error) {
	b := &contentpack.Blob{Digest: digest}
	err := r.db.QueryRowContext(ctx, `
		SELECT size_bytes, file_count, storage_key, created_at
		FROM platform_content_pack_blobs WHERE digest = $1`, digest).
		Scan(&b.SizeBytes, &b.FileCount, &b.StorageKey, &b.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, contentpack.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get platform content pack blob: %w", err)
	}
	return b, nil
}

// CreateBlob stores b unless its digest is stored.
func (r *PlatformContentPackRepository) CreateBlob(ctx context.Context, b *contentpack.Blob) (bool, error) {
	res, err := r.db.ExecContext(ctx, `
		INSERT INTO platform_content_pack_blobs (digest, size_bytes, file_count, storage_key, created_at)
		VALUES ($1, $2, $3, $4, $5) ON CONFLICT (digest) DO NOTHING`,
		b.Digest, b.SizeBytes, b.FileCount, b.StorageKey, b.CreatedAt)
	if err != nil {
		return false, fmt.Errorf("create platform content pack blob: %w", err)
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// Create stores a platform pack.
func (r *PlatformContentPackRepository) Create(ctx context.Context, p *contentpack.PlatformPack) error {
	lint, err := json.Marshal(p.Lint)
	if err != nil {
		return fmt.Errorf("encode lint report: %w", err)
	}
	_, err = r.db.ExecContext(ctx, `
		INSERT INTO platform_content_packs (id, name, version, kind, digest, tier, status, source,
			source_ref, source_digest, lint, signature, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
		p.ID.String(), p.Name, p.Version, p.Kind, p.Digest, string(p.Tier), string(p.Status),
		string(p.Source), nullString(p.SourceRef), nullString(p.SourceDigest), lint, p.Signature, p.CreatedAt)
	if err != nil {
		if isUniqueViolation(err) {
			return contentpack.ErrExists
		}
		return fmt.Errorf("create platform content pack: %w", err)
	}
	return nil
}

const platformContentPackSelect = `
	SELECT p.id, p.name, p.version, p.kind, p.digest, b.size_bytes, b.file_count, p.tier, p.status,
		p.source, p.source_ref, p.source_digest, p.lint, p.signature, p.created_at, p.revoked_at, p.revoke_reason
	FROM platform_content_packs p
	JOIN platform_content_pack_blobs b ON b.digest = p.digest`

func scanPlatformContentPack(row interface{ Scan(...any) error }) (*contentpack.PlatformPack, error) {
	var (
		p                               contentpack.PlatformPack
		id, tier, status, source        string
		sourceRef, sourceDigest, reason sql.NullString
		revokedAt                       sql.NullTime
		lint                            []byte
	)
	if err := row.Scan(&id, &p.Name, &p.Version, &p.Kind, &p.Digest, &p.SizeBytes, &p.FileCount, &tier, &status,
		&source, &sourceRef, &sourceDigest, &lint, &p.Signature, &p.CreatedAt, &revokedAt, &reason); err != nil {
		return nil, err
	}
	p.ID, _ = shared.IDFromString(id)
	p.Tier, p.Status, p.Source = contentpack.Tier(tier), contentpack.Status(status), contentpack.Source(source)
	p.SourceRef, p.SourceDigest, p.RevokeReason = sourceRef.String, sourceDigest.String, reason.String
	if err := json.Unmarshal(lint, &p.Lint); err != nil {
		return nil, fmt.Errorf("decode lint report: %w", err)
	}
	if revokedAt.Valid {
		t := revokedAt.Time
		p.RevokedAt = &t
	}
	return &p, nil
}

// GetByID returns a platform pack.
//
//getbyid:unsafe - Platform packs are a platform catalog every organization reads; no tenant_id column.
func (r *PlatformContentPackRepository) GetByID(ctx context.Context, id shared.ID) (*contentpack.PlatformPack, error) {
	p, err := scanPlatformContentPack(r.db.QueryRowContext(ctx, platformContentPackSelect+` WHERE p.id = $1`, id.String()))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, contentpack.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get platform content pack: %w", err)
	}
	return p, nil
}

// List returns a page of platform packs, newest first, and the total.
func (r *PlatformContentPackRepository) List(ctx context.Context, f contentpack.Filter, limit, offset int) ([]*contentpack.PlatformPack, int, error) {
	where := ` WHERE ($1::text = '' OR p.kind = $1) AND ($2::text = '' OR p.name = $2) AND ($3::text = '' OR p.status = $3)`
	args := []any{f.Kind, f.Name, string(f.Status)}
	var total int
	if err := r.db.QueryRowContext(ctx, `SELECT count(*) FROM platform_content_packs p`+where, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count platform content packs: %w", err)
	}
	rows, err := r.db.QueryContext(ctx, platformContentPackSelect+where+` ORDER BY p.created_at DESC, p.id DESC LIMIT $4 OFFSET $5`,
		append(args, limit, offset)...)
	if err != nil {
		return nil, 0, fmt.Errorf("list platform content packs: %w", err)
	}
	defer rows.Close()
	out := []*contentpack.PlatformPack{}
	for rows.Next() {
		p, err := scanPlatformContentPack(rows)
		if err != nil {
			return nil, 0, fmt.Errorf("list platform content packs: %w", err)
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("list platform content packs: %w", err)
	}
	return out, total, nil
}

// Revoke revokes an active pack and rolls its channels back, in one
// transaction (the pack row is locked first, so two revocations of a name
// serialize on the channel rows).
func (r *PlatformContentPackRepository) Revoke(ctx context.Context, id shared.ID, reason string, at time.Time) ([]contentpack.ChannelPointer, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("revoke platform content pack: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var name, status string
	var created time.Time
	err = tx.QueryRowContext(ctx, `SELECT name, status, created_at FROM platform_content_packs WHERE id = $1 FOR UPDATE`,
		id.String()).Scan(&name, &status, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, contentpack.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("revoke platform content pack: %w", err)
	}
	if status != string(contentpack.StatusActive) {
		return nil, contentpack.ErrNotActive
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE platform_content_packs SET status = 'revoked', revoked_at = $2, revoke_reason = $3 WHERE id = $1`,
		id.String(), at, reason); err != nil {
		return nil, fmt.Errorf("revoke platform content pack: %w", err)
	}
	// The previous good pack: the newest active pack of the name created
	// before this one.
	var prev sql.NullString
	err = tx.QueryRowContext(ctx, `
		SELECT id FROM platform_content_packs
		WHERE name = $1 AND status = 'active' AND (created_at, id) < ($2, $3)
		ORDER BY created_at DESC, id DESC LIMIT 1`, name, created, id.String()).Scan(&prev)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("revoke platform content pack: %w", err)
	}
	if prev.Valid {
		_, err = tx.ExecContext(ctx, `UPDATE platform_content_channels SET pack_id = $2, updated_at = $3 WHERE pack_id = $1`,
			id.String(), prev.String, at)
	} else {
		_, err = tx.ExecContext(ctx, `DELETE FROM platform_content_channels WHERE pack_id = $1`, id.String())
	}
	if err != nil {
		return nil, fmt.Errorf("roll back channels: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("revoke platform content pack: %w", err)
	}
	all, err := r.Channels(ctx)
	if err != nil {
		return nil, err
	}
	out := []contentpack.ChannelPointer{}
	for _, c := range all {
		if c.Name == name {
			out = append(out, c)
		}
	}
	return out, nil
}

// SetChannel points channel of the pack's name at an active pack.
func (r *PlatformContentPackRepository) SetChannel(ctx context.Context, id shared.ID, channel contentpack.Channel, at time.Time) (*contentpack.ChannelPointer, error) {
	res, err := r.db.ExecContext(ctx, `
		INSERT INTO platform_content_channels (name, channel, pack_id, updated_at)
		SELECT name, $2, id, $3 FROM platform_content_packs WHERE id = $1 AND status = 'active'
		ON CONFLICT (name, channel) DO UPDATE SET pack_id = EXCLUDED.pack_id, updated_at = EXCLUDED.updated_at`,
		id.String(), string(channel), at)
	if err != nil {
		return nil, fmt.Errorf("set platform content channel: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		if _, err := r.GetByID(ctx, id); err != nil {
			return nil, err
		}
		return nil, contentpack.ErrNotActive
	}
	all, err := r.Channels(ctx)
	if err != nil {
		return nil, err
	}
	for i := range all {
		if all[i].PackID == id && all[i].Channel == channel {
			return &all[i], nil
		}
	}
	return nil, contentpack.ErrNotFound
}

// Channels lists every channel with its pack's version and digest.
func (r *PlatformContentPackRepository) Channels(ctx context.Context) ([]contentpack.ChannelPointer, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT c.name, c.channel, c.pack_id, p.version, p.digest, c.updated_at
		FROM platform_content_channels c JOIN platform_content_packs p ON p.id = c.pack_id
		ORDER BY c.name, c.channel`)
	if err != nil {
		return nil, fmt.Errorf("list platform content channels: %w", err)
	}
	defer rows.Close()
	out := []contentpack.ChannelPointer{}
	for rows.Next() {
		var c contentpack.ChannelPointer
		var ch, pid string
		if err := rows.Scan(&c.Name, &ch, &pid, &c.Version, &c.Digest, &c.UpdatedAt); err != nil {
			return nil, fmt.Errorf("list platform content channels: %w", err)
		}
		c.Channel = contentpack.Channel(ch)
		c.PackID, _ = shared.IDFromString(pid)
		out = append(out, c)
	}
	return out, rows.Err()
}
