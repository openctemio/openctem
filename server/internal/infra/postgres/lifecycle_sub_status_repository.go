package postgres

// The finding sub-status catalog (docs/rfcs/RFC-110-tenant-lifecycles.md).
// Every statement is tenant-scoped; the category of a sub-status never
// changes (the database refuses it), so Update writes presentation only.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/findinglifecycle"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// LifecycleSubStatusRepository implements findinglifecycle.SubStatusRepository.
type LifecycleSubStatusRepository struct {
	db *DB
}

// NewLifecycleSubStatusRepository returns the repository.
func NewLifecycleSubStatusRepository(db *DB) *LifecycleSubStatusRepository {
	return &LifecycleSubStatusRepository{db: db}
}

var _ findinglifecycle.SubStatusRepository = (*LifecycleSubStatusRepository)(nil)

const lifecycleSubStatusColumns = `id, tenant_id, object_kind, canonical_status, COALESCE(closure_reason, ''), key, name,
	labels, description, color, sort_order, archived_at, created_at, created_by, updated_at, updated_by`

// Create stores a new sub-status.
func (r *LifecycleSubStatusRepository) Create(ctx context.Context, s *findinglifecycle.SubStatus) error {
	labels, err := json.Marshal(s.Labels())
	if err != nil {
		return fmt.Errorf("marshal labels: %w", err)
	}
	_, err = r.db.ExecContext(ctx, `
		INSERT INTO lifecycle_sub_statuses (id, tenant_id, object_kind, canonical_status, closure_reason, key, name,
			labels, description, color, sort_order, archived_at, created_at, created_by, updated_at, updated_by)
		VALUES ($1, $2, $3, $4, NULLIF($5, ''), $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)`,
		s.ID().String(), s.TenantID().String(), string(s.Kind()), string(s.CanonicalStatus()), string(s.ClosureReason()),
		s.Key(), s.Name(), labels, s.Description(), s.Color(), s.SortOrder(), s.ArchivedAt(),
		s.CreatedAt(), nullID(s.CreatedBy()), s.UpdatedAt(), nullID(s.UpdatedBy()))
	if err != nil {
		if isUniqueViolation(err) {
			return findinglifecycle.ErrSubStatusKeyTaken
		}
		return fmt.Errorf("create sub-status: %w", err)
	}
	return nil
}

// Update writes the presentation and archive state of a sub-status.
func (r *LifecycleSubStatusRepository) Update(ctx context.Context, s *findinglifecycle.SubStatus) error {
	labels, err := json.Marshal(s.Labels())
	if err != nil {
		return fmt.Errorf("marshal labels: %w", err)
	}
	res, err := r.db.ExecContext(ctx, `
		UPDATE lifecycle_sub_statuses
		SET name = $3, labels = $4, description = $5, color = $6, sort_order = $7, archived_at = $8,
		    updated_at = $9, updated_by = $10
		WHERE tenant_id = $1 AND id = $2`,
		s.TenantID().String(), s.ID().String(), s.Name(), labels, s.Description(), s.Color(), s.SortOrder(),
		s.ArchivedAt(), s.UpdatedAt(), nullID(s.UpdatedBy()))
	if err != nil {
		return fmt.Errorf("update sub-status: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return findinglifecycle.ErrSubStatusNotFound
	}
	return nil
}

// GetByID returns one of the tenant's sub-statuses.
func (r *LifecycleSubStatusRepository) GetByID(ctx context.Context, tenantID, id shared.ID) (*findinglifecycle.SubStatus, error) {
	row := r.db.QueryRowContext(ctx, `SELECT `+lifecycleSubStatusColumns+`
		FROM lifecycle_sub_statuses WHERE tenant_id = $1 AND id = $2`, tenantID.String(), id.String())
	s, err := scanLifecycleSubStatus(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, findinglifecycle.ErrSubStatusNotFound
	}
	return s, err
}

// List returns the tenant's sub-statuses of a kind in display order (the
// lifecycle order of their canonical status, then sort order, then name).
func (r *LifecycleSubStatusRepository) List(ctx context.Context, tenantID shared.ID, f findinglifecycle.SubStatusFilter) ([]*findinglifecycle.SubStatus, error) {
	kind := f.Kind
	if kind == "" {
		kind = findinglifecycle.ObjectKindFinding
	}
	rows, err := r.db.QueryContext(ctx, `SELECT `+lifecycleSubStatusColumns+`
		FROM lifecycle_sub_statuses
		WHERE tenant_id = $1 AND object_kind = $2 AND ($3 OR archived_at IS NULL)
		ORDER BY array_position(ARRAY['new','confirmed','in_progress','fix_applied','resolved','false_positive','accepted','duplicate']::varchar[], canonical_status),
		         sort_order, name, id
		LIMIT $4`,
		tenantID.String(), string(kind), f.IncludeArchived, 10*findinglifecycle.MaxSubStatusesPerKind)
	if err != nil {
		return nil, fmt.Errorf("list sub-statuses: %w", err)
	}
	defer rows.Close()
	out := make([]*findinglifecycle.SubStatus, 0)
	for rows.Next() {
		s, err := scanLifecycleSubStatus(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate sub-statuses: %w", err)
	}
	return out, nil
}

// CountActive counts the tenant's sub-statuses of kind that are not archived.
func (r *LifecycleSubStatusRepository) CountActive(ctx context.Context, tenantID shared.ID, kind findinglifecycle.ObjectKind) (int, error) {
	var n int
	if err := r.db.QueryRowContext(ctx, `
		SELECT count(*) FROM lifecycle_sub_statuses
		WHERE tenant_id = $1 AND object_kind = $2 AND archived_at IS NULL`,
		tenantID.String(), string(kind)).Scan(&n); err != nil {
		return 0, fmt.Errorf("count sub-statuses: %w", err)
	}
	return n, nil
}

// CountFindings counts the tenant's findings that carry the sub-status
// (idx_findings_sub_status).
func (r *LifecycleSubStatusRepository) CountFindings(ctx context.Context, tenantID, id shared.ID) (int64, error) {
	var n int64
	if err := r.db.QueryRowContext(ctx, `
		SELECT count(*) FROM findings WHERE tenant_id = $1 AND sub_status_id = $2`,
		tenantID.String(), id.String()).Scan(&n); err != nil {
		return 0, fmt.Errorf("count findings of sub-status: %w", err)
	}
	return n, nil
}

func scanLifecycleSubStatus(row interface{ Scan(...any) error }) (*findinglifecycle.SubStatus, error) {
	var (
		d                    findinglifecycle.SubStatusData
		id, tenant           string
		kind, status, reason string
		labels               []byte
		archivedAt           sql.NullTime
		createdBy, updatedBy sql.NullString
		createdAt, updatedAt time.Time
	)
	if err := row.Scan(&id, &tenant, &kind, &status, &reason, &d.Key, &d.Name, &labels, &d.Description, &d.Color,
		&d.SortOrder, &archivedAt, &createdAt, &createdBy, &updatedAt, &updatedBy); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		return nil, fmt.Errorf("scan sub-status: %w", err)
	}
	var err error
	if d.ID, err = shared.IDFromString(id); err != nil {
		return nil, fmt.Errorf("scan sub-status id: %w", err)
	}
	if d.TenantID, err = shared.IDFromString(tenant); err != nil {
		return nil, fmt.Errorf("scan sub-status tenant: %w", err)
	}
	d.Kind = findinglifecycle.ObjectKind(kind)
	d.CanonicalStatus = vulnerability.FindingStatus(status)
	d.ClosureReason = vulnerability.ClosureReason(reason)
	if len(labels) > 0 {
		if err := json.Unmarshal(labels, &d.Labels); err != nil {
			return nil, fmt.Errorf("scan sub-status labels: %w", err)
		}
	}
	if archivedAt.Valid {
		t := archivedAt.Time
		d.ArchivedAt = &t
	}
	d.CreatedAt, d.UpdatedAt = createdAt, updatedAt
	d.CreatedBy, d.UpdatedBy = optionalID(createdBy), optionalID(updatedBy)
	return findinglifecycle.ReconstituteSubStatus(d), nil
}
