package postgres

// Sealed raw reports of queued CI results and file imports
// (docs/rfcs/RFC-122-ingest-receipts.md, "Accept fast, apply async").

import (
	"context"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/ingestpayload"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// IngestPayloadRepository implements ingestpayload.Repository.
type IngestPayloadRepository struct {
	db *DB
}

var _ ingestpayload.Repository = (*IngestPayloadRepository)(nil)

// NewIngestPayloadRepository constructs the repository.
func NewIngestPayloadRepository(db *DB) *IngestPayloadRepository {
	return &IngestPayloadRepository{db: db}
}

// Put stores one sealed part.
func (r *IngestPayloadRepository) Put(ctx context.Context, p *ingestpayload.Part) error {
	if p == nil || p.TenantID.IsZero() || p.JobID.IsZero() {
		return fmt.Errorf("%w: a payload part needs a tenant and a job", shared.ErrValidation)
	}
	expires := p.ExpiresAt
	if expires.IsZero() {
		expires = time.Now().Add(ingestpayload.FailedRetention)
	}
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO ingest_payloads (job_id, part, tenant_id, name, key_id, size_bytes, digest, sealed, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (job_id, part) DO UPDATE SET
			name = EXCLUDED.name, key_id = EXCLUDED.key_id, size_bytes = EXCLUDED.size_bytes,
			digest = EXCLUDED.digest, sealed = EXCLUDED.sealed, expires_at = EXCLUDED.expires_at
		WHERE ingest_payloads.tenant_id = EXCLUDED.tenant_id`,
		p.JobID.String(), p.Part, p.TenantID.String(), truncateRunes(p.Name, 255), p.KeyID, p.SizeBytes,
		p.Digest, p.Sealed, expires)
	if err != nil {
		return fmt.Errorf("store ingest payload: %w", err)
	}
	return nil
}

// List returns a job's parts of the tenant, by part number.
func (r *IngestPayloadRepository) List(ctx context.Context, tenantID, jobID shared.ID) ([]*ingestpayload.Part, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT job_id, part, tenant_id, name, key_id, size_bytes, digest, sealed, expires_at
		FROM ingest_payloads WHERE tenant_id = $1 AND job_id = $2 ORDER BY part`,
		tenantID.String(), jobID.String())
	if err != nil {
		return nil, fmt.Errorf("list ingest payload: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []*ingestpayload.Part
	for rows.Next() {
		var (
			p             ingestpayload.Part
			job, tenant   string
			part          int
			name, keyID   string
			size          int64
			digest, bytes []byte
			expires       time.Time
		)
		if err := rows.Scan(&job, &part, &tenant, &name, &keyID, &size, &digest, &bytes, &expires); err != nil {
			return nil, fmt.Errorf("scan ingest payload: %w", err)
		}
		if p.JobID, err = shared.IDFromString(job); err != nil {
			return nil, err
		}
		if p.TenantID, err = shared.IDFromString(tenant); err != nil {
			return nil, err
		}
		p.Part, p.Name, p.KeyID, p.SizeBytes, p.Digest, p.Sealed, p.ExpiresAt = part, name, keyID, size, digest, bytes, expires
		out = append(out, &p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate ingest payload: %w", err)
	}
	return out, nil
}

// DeleteJob removes a job's parts.
func (r *IngestPayloadRepository) DeleteJob(ctx context.Context, tenantID, jobID shared.ID) error {
	if _, err := r.db.ExecContext(ctx, `DELETE FROM ingest_payloads WHERE tenant_id = $1 AND job_id = $2`,
		tenantID.String(), jobID.String()); err != nil {
		return fmt.Errorf("delete ingest payload: %w", err)
	}
	return nil
}
