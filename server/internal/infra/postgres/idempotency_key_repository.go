package postgres

// Durable Idempotency-Key store (docs/rfcs/RFC-122-ingest-receipts.md §6).
// Every statement is scoped by tenant_id.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/idempotency"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// IdempotencyKeyRepository stores Idempotency-Key records.
type IdempotencyKeyRepository struct {
	db *DB
}

// NewIdempotencyKeyRepository creates the repository.
func NewIdempotencyKeyRepository(db *DB) *IdempotencyKeyRepository {
	return &IdempotencyKeyRepository{db: db}
}

var _ idempotency.Store = (*IdempotencyKeyRepository)(nil)

// Claim inserts a pending record for the key, or takes over an expired one.
// An unexpired record of another request is returned as existing.
func (r *IdempotencyKeyRepository) Claim(ctx context.Context, s idempotency.Scope, pendingFor time.Duration) (*idempotency.Claim, *idempotency.Record, error) {
	token := shared.NewID()
	var won bool
	err := r.db.QueryRowContext(ctx, `
		INSERT INTO idempotency_keys (tenant_id, principal, route, key_hash, state, claim_token, expires_at)
		VALUES ($1, $2, $3, $4, 'pending', $5, now() + make_interval(secs => $6))
		ON CONFLICT (tenant_id, principal, route, key_hash) DO UPDATE
			SET state = 'pending', claim_token = EXCLUDED.claim_token, request_sha256 = NULL, status = NULL,
				response = NULL, receipt_id = NULL, created_at = now(), expires_at = EXCLUDED.expires_at
			WHERE idempotency_keys.expires_at < now()
		RETURNING true`,
		s.TenantID.String(), s.Principal, s.Route, s.KeyHash, token.String(), pendingFor.Seconds()).Scan(&won)
	if err == nil && won {
		return &idempotency.Claim{Scope: s, Token: token}, nil, nil
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, nil, fmt.Errorf("claim idempotency key: %w", err)
	}
	var (
		rec       idempotency.Record
		fp        sql.NullString
		status    sql.NullInt64
		receiptID sql.NullString
	)
	err = r.db.QueryRowContext(ctx, `
		SELECT state, request_sha256, status, response, receipt_id::text, expires_at
		FROM idempotency_keys
		WHERE tenant_id = $1 AND principal = $2 AND route = $3 AND key_hash = $4`,
		s.TenantID.String(), s.Principal, s.Route, s.KeyHash).Scan(&rec.State, &fp, &status, &rec.Response, &receiptID, &rec.ExpiresAt)
	if err != nil {
		// The record went away between the two statements (released): the
		// caller refuses rather than importing without a key.
		return nil, nil, fmt.Errorf("read idempotency key: %w", err)
	}
	rec.RequestSHA256 = strings.TrimSpace(fp.String)
	rec.Status = int(status.Int64)
	if receiptID.Valid {
		if id, err := shared.IDFromString(receiptID.String); err == nil {
			rec.ReceiptID = &id
		}
	}
	return nil, &rec, nil
}

// Complete stores the claimed request's answer for TTL.
func (r *IdempotencyKeyRepository) Complete(ctx context.Context, c *idempotency.Claim, fingerprint string, status int, response []byte, receiptID *shared.ID) error {
	var rid any
	if receiptID != nil {
		rid = receiptID.String()
	}
	res, err := r.db.ExecContext(ctx, `
		UPDATE idempotency_keys
		SET state = 'done', request_sha256 = $6, status = $7, response = $8, receipt_id = $9,
			expires_at = now() + make_interval(secs => $10)
		WHERE tenant_id = $1 AND principal = $2 AND route = $3 AND key_hash = $4 AND claim_token = $5 AND state = 'pending'`,
		c.Scope.TenantID.String(), c.Scope.Principal, c.Scope.Route, c.Scope.KeyHash, c.Token.String(),
		fingerprint, status, response, rid, idempotency.TTL.Seconds())
	if err != nil {
		return fmt.Errorf("complete idempotency key: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return shared.ErrNotFound
	}
	return nil
}

// Release deletes the claimed pending record.
func (r *IdempotencyKeyRepository) Release(ctx context.Context, c *idempotency.Claim) error {
	_, err := r.db.ExecContext(ctx, `
		DELETE FROM idempotency_keys
		WHERE tenant_id = $1 AND principal = $2 AND route = $3 AND key_hash = $4 AND claim_token = $5 AND state = 'pending'`,
		c.Scope.TenantID.String(), c.Scope.Principal, c.Scope.Route, c.Scope.KeyHash, c.Token.String())
	if err != nil {
		return fmt.Errorf("release idempotency key: %w", err)
	}
	return nil
}

// PurgeExpiredForPlatform deletes up to limit expired records (all tenants:
// a platform retention job).
func (r *IdempotencyKeyRepository) PurgeExpiredForPlatform(ctx context.Context, before time.Time, limit int) (int64, error) {
	res, err := r.db.ExecContext(ctx, `
		DELETE FROM idempotency_keys
		WHERE ctid IN (SELECT ctid FROM idempotency_keys WHERE expires_at < $1 LIMIT $2)`, before, limit)
	if err != nil {
		return 0, fmt.Errorf("purge idempotency keys: %w", err)
	}
	return res.RowsAffected()
}
