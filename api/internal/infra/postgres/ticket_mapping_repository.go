package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/ticketmap"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// TicketMappingRepository stores ticket mapping profiles and their versions.
// Every query is tenant-scoped.
type TicketMappingRepository struct {
	db *DB
}

// NewTicketMappingRepository creates the repository.
func NewTicketMappingRepository(db *DB) *TicketMappingRepository {
	return &TicketMappingRepository{db: db}
}

var _ ticketmap.Repository = (*TicketMappingRepository)(nil)

// ErrTicketMappingProfileNotFound is returned for a missing profile or version.
var ErrTicketMappingProfileNotFound = fmt.Errorf("%w: mapping profile not found", shared.ErrNotFound)

const tmpCols = `id, tenant_id, integration_id, object_kind, project_id, project_key, issue_type_id, issue_type,
	name, published_version, draft_version, dry_run, drifted, created_by, created_at, updated_at`

const tmvCols = `profile_id, tenant_id, version, state, spec, snapshot, note, created_by, created_at, published_by, published_at`

// CreateProfile inserts a profile and its first draft in one transaction.
func (r *TicketMappingRepository) CreateProfile(ctx context.Context, p *ticketmap.Profile, first *ticketmap.Version) error {
	return r.db.Transaction(ctx, func(tx *sql.Tx) error {
		if first != nil {
			p.DraftVersion = first.Version
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO ticket_mapping_profiles (`+tmpCols+`)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`,
			p.ID.String(), p.TenantID.String(), p.IntegrationID.String(), string(p.ObjectKind), p.ProjectID, p.ProjectKey,
			p.IssueTypeID, p.IssueType, p.Name, p.PublishedVersion, p.DraftVersion, p.DryRun, p.Drifted,
			nullID(p.CreatedBy), p.CreatedAt, p.UpdatedAt)
		if err != nil {
			if isUniqueViolation(err) {
				return fmt.Errorf("%w: a mapping profile for this destination already exists", shared.ErrConflict)
			}
			return fmt.Errorf("create mapping profile: %w", err)
		}
		if first == nil {
			return nil
		}
		return insertVersion(ctx, tx, first)
	})
}

func insertVersion(ctx context.Context, tx *sql.Tx, v *ticketmap.Version) error {
	spec, err := json.Marshal(v.Spec)
	if err != nil {
		return fmt.Errorf("encode spec: %w", err)
	}
	var snap any
	if v.Snapshot != nil {
		b, err := json.Marshal(v.Snapshot)
		if err != nil {
			return fmt.Errorf("encode snapshot: %w", err)
		}
		snap = b
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO ticket_mapping_versions (`+tmvCols+`)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
		v.ProfileID.String(), v.TenantID.String(), v.Version, v.State, spec, snap, v.Note,
		nullID(v.CreatedBy), v.CreatedAt, nullID(v.PublishedBy), v.PublishedAt)
	if err != nil {
		return fmt.Errorf("insert mapping version: %w", err)
	}
	return nil
}

func scanProfile(s rowScanner) (*ticketmap.Profile, error) {
	var (
		p                    ticketmap.Profile
		id, tid, iid         string
		kind                 string
		createdBy            sql.NullString
		createdAt, updatedAt time.Time
	)
	if err := s.Scan(&id, &tid, &iid, &kind, &p.ProjectID, &p.ProjectKey, &p.IssueTypeID, &p.IssueType,
		&p.Name, &p.PublishedVersion, &p.DraftVersion, &p.DryRun, &p.Drifted, &createdBy, &createdAt, &updatedAt); err != nil {
		return nil, err
	}
	p.ID, _ = shared.IDFromString(id)
	p.TenantID, _ = shared.IDFromString(tid)
	p.IntegrationID, _ = shared.IDFromString(iid)
	p.ObjectKind = ticketmap.ObjectKind(kind)
	if createdBy.Valid {
		if u, err := shared.IDFromString(createdBy.String); err == nil {
			p.CreatedBy = &u
		}
	}
	p.CreatedAt, p.UpdatedAt = createdAt, updatedAt
	return &p, nil
}

func scanVersion(s rowScanner) (*ticketmap.Version, error) {
	var (
		v                      ticketmap.Version
		pid, tid               string
		spec                   []byte
		snap                   []byte
		createdBy, publishedBy sql.NullString
		publishedAt            sql.NullTime
	)
	if err := s.Scan(&pid, &tid, &v.Version, &v.State, &spec, &snap, &v.Note, &createdBy, &v.CreatedAt, &publishedBy, &publishedAt); err != nil {
		return nil, err
	}
	v.ProfileID, _ = shared.IDFromString(pid)
	v.TenantID, _ = shared.IDFromString(tid)
	if err := json.Unmarshal(spec, &v.Spec); err != nil {
		return nil, fmt.Errorf("decode spec: %w", err)
	}
	if len(snap) > 0 {
		var m ticketmap.ProjectMeta
		if err := json.Unmarshal(snap, &m); err == nil {
			v.Snapshot = &m
		}
	}
	if createdBy.Valid {
		if u, err := shared.IDFromString(createdBy.String); err == nil {
			v.CreatedBy = &u
		}
	}
	if publishedBy.Valid {
		if u, err := shared.IDFromString(publishedBy.String); err == nil {
			v.PublishedBy = &u
		}
	}
	if publishedAt.Valid {
		t := publishedAt.Time
		v.PublishedAt = &t
	}
	return &v, nil
}

// GetProfile loads one profile of the tenant.
func (r *TicketMappingRepository) GetProfile(ctx context.Context, tenantID, id shared.ID) (*ticketmap.Profile, error) {
	p, err := scanProfile(r.db.QueryRowContext(ctx, `SELECT `+tmpCols+` FROM ticket_mapping_profiles
		WHERE tenant_id = $1 AND id = $2`, tenantID.String(), id.String()))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrTicketMappingProfileNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get mapping profile: %w", err)
	}
	return p, nil
}

// FindForDestination loads the profile of one destination.
func (r *TicketMappingRepository) FindForDestination(ctx context.Context, tenantID, integrationID shared.ID, kind ticketmap.ObjectKind, projectKey, issueTypeID string) (*ticketmap.Profile, error) {
	p, err := scanProfile(r.db.QueryRowContext(ctx, `SELECT `+tmpCols+` FROM ticket_mapping_profiles
		WHERE tenant_id = $1 AND integration_id = $2 AND object_kind = $3 AND project_key = $4 AND issue_type_id = $5`,
		tenantID.String(), integrationID.String(), string(kind), projectKey, issueTypeID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrTicketMappingProfileNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("find mapping profile: %w", err)
	}
	return p, nil
}

// ListProfiles lists the tenant's profiles.
func (r *TicketMappingRepository) ListProfiles(ctx context.Context, tenantID shared.ID, f ticketmap.ProfileFilter, page pagination.Pagination) (pagination.Result[*ticketmap.Profile], error) {
	where := `tenant_id = $1`
	args := []any{tenantID.String()}
	if f.IntegrationID != nil {
		args = append(args, f.IntegrationID.String())
		where += fmt.Sprintf(" AND integration_id = $%d", len(args))
	}
	if f.ObjectKind != "" {
		args = append(args, string(f.ObjectKind))
		where += fmt.Sprintf(" AND object_kind = $%d", len(args))
	}
	if f.ProjectKey != "" {
		args = append(args, f.ProjectKey)
		where += fmt.Sprintf(" AND project_key = $%d", len(args))
	}
	var total int64
	if err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM ticket_mapping_profiles WHERE `+where, args...).Scan(&total); err != nil {
		return pagination.Result[*ticketmap.Profile]{}, fmt.Errorf("count mapping profiles: %w", err)
	}
	args = append(args, page.Limit(), page.Offset())
	rows, err := r.db.QueryContext(ctx, `SELECT `+tmpCols+` FROM ticket_mapping_profiles WHERE `+where+
		fmt.Sprintf(` ORDER BY project_key, object_kind, issue_type LIMIT $%d OFFSET $%d`, len(args)-1, len(args)), args...)
	if err != nil {
		return pagination.Result[*ticketmap.Profile]{}, fmt.Errorf("list mapping profiles: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := make([]*ticketmap.Profile, 0)
	for rows.Next() {
		p, err := scanProfile(rows)
		if err != nil {
			return pagination.Result[*ticketmap.Profile]{}, fmt.Errorf("scan mapping profile: %w", err)
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return pagination.Result[*ticketmap.Profile]{}, fmt.Errorf("list mapping profiles: %w", err)
	}
	return pagination.NewResult(out, total, page), nil
}

// DeleteProfile deletes a profile and its versions.
func (r *TicketMappingRepository) DeleteProfile(ctx context.Context, tenantID, id shared.ID) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM ticket_mapping_profiles WHERE tenant_id = $1 AND id = $2`, tenantID.String(), id.String())
	if err != nil {
		return fmt.Errorf("delete mapping profile: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrTicketMappingProfileNotFound
	}
	return nil
}

func (r *TicketMappingRepository) setFlag(ctx context.Context, tenantID, id shared.ID, col string, v bool) error {
	res, err := r.db.ExecContext(ctx, `UPDATE ticket_mapping_profiles SET `+col+` = $3, updated_at = now()
		WHERE tenant_id = $1 AND id = $2`, tenantID.String(), id.String(), v)
	if err != nil {
		return fmt.Errorf("update mapping profile: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrTicketMappingProfileNotFound
	}
	return nil
}

// SetDryRun switches the published version between dry run and live.
func (r *TicketMappingRepository) SetDryRun(ctx context.Context, tenantID, id shared.ID, dryRun bool) error {
	return r.setFlag(ctx, tenantID, id, "dry_run", dryRun)
}

// SetDrifted records whether the tracker changed under the published version.
func (r *TicketMappingRepository) SetDrifted(ctx context.Context, tenantID, id shared.ID, drifted bool) error {
	return r.setFlag(ctx, tenantID, id, "drifted", drifted)
}

// GetVersion loads one version.
func (r *TicketMappingRepository) GetVersion(ctx context.Context, tenantID, profileID shared.ID, version int) (*ticketmap.Version, error) {
	v, err := scanVersion(r.db.QueryRowContext(ctx, `SELECT `+tmvCols+` FROM ticket_mapping_versions
		WHERE tenant_id = $1 AND profile_id = $2 AND version = $3`, tenantID.String(), profileID.String(), version))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrTicketMappingProfileNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get mapping version: %w", err)
	}
	return v, nil
}

// ListVersions lists a profile's versions, newest first (at most 200).
func (r *TicketMappingRepository) ListVersions(ctx context.Context, tenantID, profileID shared.ID) ([]*ticketmap.Version, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT `+tmvCols+` FROM ticket_mapping_versions
		WHERE tenant_id = $1 AND profile_id = $2 ORDER BY version DESC LIMIT 200`, tenantID.String(), profileID.String())
	if err != nil {
		return nil, fmt.Errorf("list mapping versions: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []*ticketmap.Version
	for rows.Next() {
		v, err := scanVersion(rows)
		if err != nil {
			return nil, fmt.Errorf("scan mapping version: %w", err)
		}
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list mapping versions: %w", err)
	}
	return out, nil
}

// lockProfile locks the profile row for a version change.
func lockProfile(ctx context.Context, tx *sql.Tx, tenantID, profileID shared.ID) (*ticketmap.Profile, error) {
	p, err := scanProfile(tx.QueryRowContext(ctx, `SELECT `+tmpCols+` FROM ticket_mapping_profiles
		WHERE tenant_id = $1 AND id = $2 FOR UPDATE`, tenantID.String(), profileID.String()))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrTicketMappingProfileNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("lock mapping profile: %w", err)
	}
	return p, nil
}

// SaveDraft creates or replaces the open draft. expectedDraft must equal the
// profile's current draft number (0 when none is open), so two editors cannot
// overwrite each other.
func (r *TicketMappingRepository) SaveDraft(ctx context.Context, tenantID, profileID shared.ID, spec ticketmap.Spec, snapshot *ticketmap.ProjectMeta, note string, by *shared.ID, expectedDraft int) (*ticketmap.Version, error) {
	var out *ticketmap.Version
	err := r.db.Transaction(ctx, func(tx *sql.Tx) error {
		p, err := lockProfile(ctx, tx, tenantID, profileID)
		if err != nil {
			return err
		}
		if p.DraftVersion != expectedDraft {
			return ticketmap.ErrDraftConflict
		}
		v := &ticketmap.Version{ProfileID: profileID, TenantID: tenantID, State: ticketmap.VersionDraft,
			Spec: spec, Snapshot: snapshot, Note: note, CreatedBy: by, CreatedAt: time.Now().UTC()}
		if p.DraftVersion > 0 {
			v.Version = p.DraftVersion
			if _, err := tx.ExecContext(ctx, `DELETE FROM ticket_mapping_versions
				WHERE tenant_id = $1 AND profile_id = $2 AND version = $3 AND state = 'draft'`,
				tenantID.String(), profileID.String(), p.DraftVersion); err != nil {
				return fmt.Errorf("replace draft: %w", err)
			}
		} else {
			var maxV int
			if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(version), 0) FROM ticket_mapping_versions
				WHERE tenant_id = $1 AND profile_id = $2`, tenantID.String(), profileID.String()).Scan(&maxV); err != nil {
				return fmt.Errorf("next version: %w", err)
			}
			v.Version = maxV + 1
		}
		if err := insertVersion(ctx, tx, v); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE ticket_mapping_profiles SET draft_version = $3, updated_at = now()
			WHERE tenant_id = $1 AND id = $2`, tenantID.String(), profileID.String(), v.Version); err != nil {
			return fmt.Errorf("update profile draft: %w", err)
		}
		out = v
		return nil
	})
	return out, err
}

// Publish publishes the open draft (it must be version draft) and supersedes
// the previous published version.
func (r *TicketMappingRepository) Publish(ctx context.Context, tenantID, profileID shared.ID, draft int, by *shared.ID) (*ticketmap.Version, error) {
	var out *ticketmap.Version
	err := r.db.Transaction(ctx, func(tx *sql.Tx) error {
		p, err := lockProfile(ctx, tx, tenantID, profileID)
		if err != nil {
			return err
		}
		if p.DraftVersion == 0 || p.DraftVersion != draft {
			return ticketmap.ErrDraftConflict
		}
		if _, err := tx.ExecContext(ctx, `UPDATE ticket_mapping_versions SET state = 'superseded'
			WHERE tenant_id = $1 AND profile_id = $2 AND state = 'published'`, tenantID.String(), profileID.String()); err != nil {
			return fmt.Errorf("supersede: %w", err)
		}
		now := time.Now().UTC()
		if _, err := tx.ExecContext(ctx, `UPDATE ticket_mapping_versions SET state = 'published', published_by = $4, published_at = $5
			WHERE tenant_id = $1 AND profile_id = $2 AND version = $3 AND state = 'draft'`,
			tenantID.String(), profileID.String(), draft, nullID(by), now); err != nil {
			return fmt.Errorf("publish: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE ticket_mapping_profiles
			SET published_version = $3, draft_version = 0, drifted = false, updated_at = now()
			WHERE tenant_id = $1 AND id = $2`, tenantID.String(), profileID.String(), draft); err != nil {
			return fmt.Errorf("update profile: %w", err)
		}
		v, err := scanVersion(tx.QueryRowContext(ctx, `SELECT `+tmvCols+` FROM ticket_mapping_versions
			WHERE tenant_id = $1 AND profile_id = $2 AND version = $3`, tenantID.String(), profileID.String(), draft))
		if err != nil {
			return fmt.Errorf("reload version: %w", err)
		}
		out = v
		return nil
	})
	return out, err
}

// DiscardDraft deletes the open draft.
func (r *TicketMappingRepository) DiscardDraft(ctx context.Context, tenantID, profileID shared.ID) error {
	return r.db.Transaction(ctx, func(tx *sql.Tx) error {
		p, err := lockProfile(ctx, tx, tenantID, profileID)
		if err != nil {
			return err
		}
		if p.DraftVersion == 0 {
			return nil
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM ticket_mapping_versions
			WHERE tenant_id = $1 AND profile_id = $2 AND state = 'draft'`, tenantID.String(), profileID.String()); err != nil {
			return fmt.Errorf("discard draft: %w", err)
		}
		_, err = tx.ExecContext(ctx, `UPDATE ticket_mapping_profiles SET draft_version = 0, updated_at = now()
			WHERE tenant_id = $1 AND id = $2`, tenantID.String(), profileID.String())
		if err != nil {
			return fmt.Errorf("update profile: %w", err)
		}
		return nil
	})
}
