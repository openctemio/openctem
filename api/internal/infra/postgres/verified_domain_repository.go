package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/verifieddomain"
)

// VerifiedDomainRepository implements verifieddomain.Repository.
type VerifiedDomainRepository struct {
	db *DB
}

// NewVerifiedDomainRepository creates a new repository.
func NewVerifiedDomainRepository(db *DB) *VerifiedDomainRepository {
	return &VerifiedDomainRepository{db: db}
}

var _ verifieddomain.Repository = (*VerifiedDomainRepository)(nil)

const vdSelectFields = `
	id, tenant_id, domain, verification_token, status,
	verified_at, last_checked_at, created_at, updated_at
`

func (r *VerifiedDomainRepository) Create(ctx context.Context, d *verifieddomain.VerifiedDomain) error {
	query := `
		INSERT INTO verified_domains (
			id, tenant_id, domain, verification_token, status,
			verified_at, last_checked_at, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`
	_, err := r.db.ExecContext(ctx, query,
		d.ID(), d.TenantID(), d.Domain(), d.VerificationToken(), string(d.Status()),
		nullTimePtr(d.VerifiedAt()), nullTimePtr(d.LastCheckedAt()),
		d.CreatedAt(), d.UpdatedAt(),
	)
	if err != nil {
		if isUniqueViolation(err) {
			return verifieddomain.ErrAlreadyExists
		}
		return fmt.Errorf("create verified domain: %w", err)
	}
	return nil
}

func (r *VerifiedDomainRepository) Update(ctx context.Context, d *verifieddomain.VerifiedDomain) error {
	query := `
		UPDATE verified_domains SET
			status = $3, verified_at = $4, last_checked_at = $5, updated_at = $6
		WHERE id = $1 AND tenant_id = $2
	`
	result, err := r.db.ExecContext(ctx, query,
		d.ID(), d.TenantID(), string(d.Status()),
		nullTimePtr(d.VerifiedAt()), nullTimePtr(d.LastCheckedAt()), d.UpdatedAt(),
	)
	if err != nil {
		return fmt.Errorf("update verified domain: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rows == 0 {
		return verifieddomain.ErrNotFound
	}
	return nil
}

func (r *VerifiedDomainRepository) Delete(ctx context.Context, tenantID, id shared.ID) error {
	result, err := r.db.ExecContext(ctx,
		"DELETE FROM verified_domains WHERE id = $1 AND tenant_id = $2", id, tenantID)
	if err != nil {
		return fmt.Errorf("delete verified domain: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rows == 0 {
		return verifieddomain.ErrNotFound
	}
	return nil
}

func (r *VerifiedDomainRepository) GetByID(ctx context.Context, tenantID, id shared.ID) (*verifieddomain.VerifiedDomain, error) {
	query := fmt.Sprintf("SELECT %s FROM verified_domains WHERE id = $1 AND tenant_id = $2", vdSelectFields)
	return r.scanVD(r.db.QueryRowContext(ctx, query, id, tenantID))
}

func (r *VerifiedDomainRepository) GetByTenantAndDomain(ctx context.Context, tenantID shared.ID, domain string) (*verifieddomain.VerifiedDomain, error) {
	query := fmt.Sprintf("SELECT %s FROM verified_domains WHERE tenant_id = $1 AND domain = $2", vdSelectFields)
	return r.scanVD(r.db.QueryRowContext(ctx, query, tenantID, domain))
}

func (r *VerifiedDomainRepository) ListByTenant(ctx context.Context, tenantID shared.ID) ([]*verifieddomain.VerifiedDomain, error) {
	query := fmt.Sprintf("SELECT %s FROM verified_domains WHERE tenant_id = $1 ORDER BY created_at ASC", vdSelectFields)
	rows, err := r.db.QueryContext(ctx, query, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list verified domains: %w", err)
	}
	defer rows.Close()
	return r.scanRows(rows)
}

func (r *VerifiedDomainRepository) ListDueForRecheck(ctx context.Context, checkedBefore time.Time, limit int) ([]*verifieddomain.VerifiedDomain, error) {
	if limit <= 0 {
		limit = 100
	}
	query := fmt.Sprintf(`
		SELECT %s FROM verified_domains
		WHERE status = $1 AND (last_checked_at IS NULL OR last_checked_at < $2)
		ORDER BY last_checked_at ASC NULLS FIRST
		LIMIT $3
	`, vdSelectFields)
	rows, err := r.db.QueryContext(ctx, query, string(verifieddomain.StatusVerified), checkedBefore, limit)
	if err != nil {
		return nil, fmt.Errorf("list verified domains due for recheck: %w", err)
	}
	defer rows.Close()
	return r.scanRows(rows)
}

func (r *VerifiedDomainRepository) scanRows(rows *sql.Rows) ([]*verifieddomain.VerifiedDomain, error) {
	var result []*verifieddomain.VerifiedDomain
	for rows.Next() {
		vd, err := r.scanVD(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, vd)
	}
	return result, rows.Err()
}

// scanVD scans a single row via the shared rowScanner interface (works for both
// *sql.Row and *sql.Rows).
func (r *VerifiedDomainRepository) scanVD(scanner rowScanner) (*verifieddomain.VerifiedDomain, error) {
	var (
		id, tenantID          string
		domain, token, status string
		verifiedAt, checkedAt sql.NullTime
		createdAt, updatedAt  time.Time
	)
	err := scanner.Scan(
		&id, &tenantID, &domain, &token, &status,
		&verifiedAt, &checkedAt, &createdAt, &updatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, verifieddomain.ErrNotFound
		}
		return nil, fmt.Errorf("scan verified domain: %w", err)
	}

	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("parse tenant id: %w", err)
	}
	vid, err := shared.IDFromString(id)
	if err != nil {
		return nil, fmt.Errorf("parse id: %w", err)
	}

	return verifieddomain.Reconstruct(
		vid, tid, domain, token, verifieddomain.Status(status),
		nullTimeValue(verifiedAt), nullTimeValue(checkedAt),
		createdAt, updatedAt,
	), nil
}
