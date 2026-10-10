package postgres

// Bug-bounty programs (RFC-065): programs, their program exclusions and their
// scope entries. Every statement carries the tenant; an import, a re-import
// and a status change are one transaction each.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/bountyprogram"
	"github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// BountyProgramRepository implements bountyprogram.Repository.
type BountyProgramRepository struct {
	db      *DB
	targets *ScopeTargetRepository
}

var _ bountyprogram.Repository = (*BountyProgramRepository)(nil)

// NewBountyProgramRepository creates the repository.
func NewBountyProgramRepository(db *DB) *BountyProgramRepository {
	return &BountyProgramRepository{db: db, targets: NewScopeTargetRepository(db)}
}

const bountyProgramColumns = `id, tenant_id, name, platform, handle, program_url, status, scope_source,
	authoritative, rules, scope_items, terms_sha256, accepted_by, accepted_at, group_id,
	created_by, created_at, updated_at, visibility, terms_text, public_program_id`

// bountyProgramSyncColumns are read after bountyProgramColumns.
const bountyProgramSyncColumns = `, sync_url, sync_handle, sync_username, sync_token_encrypted,
	last_synced_at, last_sync_error, pending_terms_sha256, pending_scope_items`

func (r *BountyProgramRepository) inTx(ctx context.Context, fn func(tx *sql.Tx) error) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}

// Import writes a new program, its group (with the importer as member), its
// entries and its program exclusions.
func (r *BountyProgramRepository) Import(ctx context.Context, w bountyprogram.ImportWrite) error {
	p := w.Program
	return r.inTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO groups (id, tenant_id, name, slug, description, group_type, is_active)
			VALUES ($1, $2, $3, $4, $5, 'project', true)`,
			w.Group.ID.String(), p.TenantID.String(), w.Group.Name, w.Group.Slug,
			"Members work on the program "+p.Name+" (RFC-065)"); err != nil {
			if isUniqueViolation(err) {
				return bountyprogram.ErrNameTaken
			}
			return fmt.Errorf("create program group: %w", err)
		}
		if w.Group.Member != nil {
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO group_members (group_id, user_id, role, added_by) VALUES ($1, $2, 'lead', $2)
				ON CONFLICT DO NOTHING`, w.Group.ID.String(), w.Group.Member.String()); err != nil {
				return fmt.Errorf("add program member: %w", err)
			}
		}
		gid := w.Group.ID
		p.GroupID = &gid
		if err := insertProgram(ctx, tx, p); err != nil {
			return err
		}
		for _, t := range w.Entries {
			if err := insertScopeTarget(ctx, tx, t); err != nil {
				return fmt.Errorf("entry %s: %w", t.Pattern(), err)
			}
		}
		return insertProgramExclusions(ctx, tx, w.Exclusions)
	})
}

func insertProgram(ctx context.Context, tx *sql.Tx, p *bountyprogram.Program) error {
	rules, items, err := programJSON(p)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO bounty_programs (`+bountyProgramColumns+`)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21)`,
		p.ID.String(), p.TenantID.String(), p.Name, p.Platform, p.Handle, p.ProgramURL, string(p.Status),
		p.ScopeSource, p.Authoritative, rules, items, p.TermsSHA256, nullIDPtr(p.AcceptedBy), p.AcceptedAt,
		nullIDPtr(p.GroupID), nullIDPtr(p.CreatedBy), p.CreatedAt, p.UpdatedAt, visibilityOf(p), p.TermsText,
		nullIDPtr(p.PublicProgramID))
	if err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code == "23505" && pqErr.Constraint == "uq_bounty_programs_public" {
			return bountyprogram.ErrAlreadySubscribed
		}
		if isUniqueViolation(err) {
			return bountyprogram.ErrNameTaken
		}
		return fmt.Errorf("create program: %w", err)
	}
	return nil
}

func programJSON(p *bountyprogram.Program) (rules, items []byte, err error) {
	if rules, err = json.Marshal(p.Rules); err != nil {
		return nil, nil, fmt.Errorf("encode rules: %w", err)
	}
	its := p.ScopeItems
	if its == nil {
		its = []bountyprogram.Item{}
	}
	if items, err = json.Marshal(its); err != nil {
		return nil, nil, fmt.Errorf("encode scope items: %w", err)
	}
	return rules, items, nil
}

func insertProgramExclusions(ctx context.Context, tx *sql.Tx, ex []bountyprogram.Exclusion) error {
	for _, e := range ex {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO bounty_program_exclusions (id, tenant_id, program_id, target_type, pattern, reason, created_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
			ON CONFLICT (program_id, target_type, pattern) DO NOTHING`,
			e.ID.String(), e.TenantID.String(), e.ProgramID.String(), string(e.TargetType), e.Pattern, e.Reason, e.CreatedAt); err != nil {
			return fmt.Errorf("program exclusion %s: %w", e.Pattern, err)
		}
	}
	return nil
}

// updateProgram writes the mutable columns of a program.
func updateProgram(ctx context.Context, tx *sql.Tx, p *bountyprogram.Program) error {
	rules, items, err := programJSON(p)
	if err != nil {
		return err
	}
	pendingTerms, pendingItems, err := pendingJSON(p)
	if err != nil {
		return err
	}
	res, err := tx.ExecContext(ctx, `
		UPDATE bounty_programs SET program_url = $3, status = $4, rules = $5, scope_items = $6,
		       terms_sha256 = $7, accepted_by = $8, accepted_at = $9, updated_at = $10,
		       pending_terms_sha256 = $11, pending_scope_items = $12, terms_text = $13
		WHERE tenant_id = $1 AND id = $2`,
		p.TenantID.String(), p.ID.String(), p.ProgramURL, string(p.Status), rules, items,
		p.TermsSHA256, nullIDPtr(p.AcceptedBy), p.AcceptedAt, p.UpdatedAt, pendingTerms, pendingItems, p.TermsText)
	if err != nil {
		return fmt.Errorf("update program: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return bountyprogram.ErrNotFound
	}
	return nil
}

func pendingJSON(p *bountyprogram.Program) (any, any, error) {
	if p.Pending == nil {
		return nil, nil, nil
	}
	items := p.Pending.Items
	if items == nil {
		items = []bountyprogram.Item{}
	}
	b, err := json.Marshal(items)
	if err != nil {
		return nil, nil, fmt.Errorf("encode pending items: %w", err)
	}
	return p.Pending.TermsSHA256, b, nil
}

// SaveSync writes the program's source settings, sync state and pending
// terms.
func (r *BountyProgramRepository) SaveSync(ctx context.Context, p *bountyprogram.Program) error {
	pendingTerms, pendingItems, err := pendingJSON(p)
	if err != nil {
		return err
	}
	ns := func(v string) any {
		if v == "" {
			return nil
		}
		return v
	}
	res, err := r.db.ExecContext(ctx, `
		UPDATE bounty_programs SET scope_source = $3, sync_url = $4, sync_handle = $5, sync_username = $6,
		       sync_token_encrypted = $7, last_synced_at = $8, last_sync_error = $9,
		       pending_terms_sha256 = $10, pending_scope_items = $11, updated_at = $12
		WHERE tenant_id = $1 AND id = $2`,
		p.TenantID.String(), p.ID.String(), p.ScopeSource, ns(p.Sync.URL), ns(p.Sync.Handle), ns(p.Sync.Username),
		ns(p.Sync.TokenEncrypted), p.Sync.LastSyncedAt, bountyprogram.ClipSyncError(p.Sync.LastError),
		pendingTerms, pendingItems, p.UpdatedAt)
	if err != nil {
		return fmt.Errorf("save program sync: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return bountyprogram.ErrNotFound
	}
	return nil
}

// SyncDue lists the active programs with a source, least recently synced
// first (the controller).
func (r *BountyProgramRepository) SyncDue(ctx context.Context, olderThan time.Time, limit int) ([]bountyprogram.ProgramRef, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT tenant_id::text, id::text FROM bounty_programs
		WHERE scope_source IN ('program_api', 'program_file') AND status = 'active'
		  AND (last_synced_at IS NULL OR last_synced_at < $1)
		ORDER BY last_synced_at NULLS FIRST LIMIT $2`, olderThan, limit)
	if err != nil {
		return nil, fmt.Errorf("list programs to sync: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []bountyprogram.ProgramRef
	for rows.Next() {
		var t, p string
		if err := rows.Scan(&t, &p); err != nil {
			return nil, err
		}
		tid, e1 := shared.IDFromString(t)
		pid, e2 := shared.IDFromString(p)
		if e1 == nil && e2 == nil {
			out = append(out, bountyprogram.ProgramRef{TenantID: tid, ProgramID: pid})
		}
	}
	return out, rows.Err()
}

// ReplaceScope applies a re-import.
func (r *BountyProgramRepository) ReplaceScope(ctx context.Context, w bountyprogram.ScopeWrite) error {
	p := w.Program
	return r.inTx(ctx, func(tx *sql.Tx) error {
		if err := updateProgram(ctx, tx, p); err != nil {
			return err
		}
		if len(w.DeleteEntryIDs) > 0 {
			ids := make([]string, 0, len(w.DeleteEntryIDs))
			for _, id := range w.DeleteEntryIDs {
				ids = append(ids, id.String())
			}
			if _, err := tx.ExecContext(ctx, `
				DELETE FROM scope_targets
				WHERE tenant_id = $1 AND program_id = $2 AND id = ANY($3::uuid[])`,
				p.TenantID.String(), p.ID.String(), pq.Array(ids)); err != nil {
				return fmt.Errorf("delete removed entries: %w", err)
			}
		}
		for _, t := range w.CreateEntries {
			if err := insertScopeTarget(ctx, tx, t); err != nil {
				return fmt.Errorf("entry %s: %w", t.Pattern(), err)
			}
		}
		if w.DeactivateEntries {
			if _, err := tx.ExecContext(ctx, `
				UPDATE scope_targets SET status = 'inactive', updated_at = now()
				WHERE tenant_id = $1 AND program_id = $2 AND status = 'active'`,
				p.TenantID.String(), p.ID.String()); err != nil {
				return fmt.Errorf("deactivate program entries: %w", err)
			}
		}
		if _, err := tx.ExecContext(ctx, `
			DELETE FROM bounty_program_exclusions WHERE tenant_id = $1 AND program_id = $2`,
			p.TenantID.String(), p.ID.String()); err != nil {
			return fmt.Errorf("replace program exclusions: %w", err)
		}
		return insertProgramExclusions(ctx, tx, w.Exclusions)
	})
}

// SetStatus updates the program and the status of every one of its
// entries.
func (r *BountyProgramRepository) SetStatus(ctx context.Context, p *bountyprogram.Program, entryStatus scope.Status) error {
	if entryStatus != scope.StatusActive && entryStatus != scope.StatusInactive {
		return fmt.Errorf("%w: entry status must be active or inactive", shared.ErrValidation)
	}
	return r.inTx(ctx, func(tx *sql.Tx) error {
		if err := updateProgram(ctx, tx, p); err != nil {
			return err
		}
		// An entry becoming active is approved now (it authorizes from now).
		if _, err := tx.ExecContext(ctx, `
			UPDATE scope_targets
			SET status = $3::text, updated_at = now(),
			    approved_at = CASE WHEN $3::text = 'active' THEN now() ELSE approved_at END
			WHERE tenant_id = $1 AND program_id = $2 AND status IN ('active', 'inactive')`,
			p.TenantID.String(), p.ID.String(), string(entryStatus)); err != nil {
			return fmt.Errorf("set program entries %s: %w", entryStatus, err)
		}
		return nil
	})
}

// GetByID returns one program of the tenant.
func (r *BountyProgramRepository) GetByID(ctx context.Context, tenantID, id shared.ID) (*bountyprogram.Program, error) {
	row := r.db.QueryRowContext(ctx, `SELECT `+bountyProgramColumns+bountyProgramSyncColumns+` FROM bounty_programs WHERE tenant_id = $1 AND id = $2`,
		tenantID.String(), id.String())
	p, err := scanProgram(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, bountyprogram.ErrNotFound
	}
	return p, err
}

// List lists the tenant's programs (only the user's programs with memberOf).
func (r *BountyProgramRepository) List(ctx context.Context, tenantID shared.ID, memberOf *shared.ID) ([]*bountyprogram.Program, error) {
	q := `SELECT ` + bountyProgramColumns + bountyProgramSyncColumns + ` FROM bounty_programs p WHERE p.tenant_id = $1`
	args := []any{tenantID.String()}
	if memberOf != nil {
		q += ` AND EXISTS (SELECT 1 FROM group_members gm JOIN groups g ON g.id = gm.group_id
		                   WHERE g.tenant_id = p.tenant_id AND g.id = p.group_id AND g.is_active AND gm.user_id = $2)`
		args = append(args, memberOf.String())
	}
	q += ` ORDER BY lower(p.name) LIMIT 500`
	rows, err := r.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("list programs: %w", err)
	}
	defer rows.Close()
	var out []*bountyprogram.Program
	for rows.Next() {
		p, err := scanProgram(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func scanProgram(row interface{ Scan(...any) error }) (*bountyprogram.Program, error) {
	var (
		p                              bountyprogram.Program
		id, tenantID, status, vis      string
		rules, items                   []byte
		acceptedBy, groupID, createdBy sql.NullString
		publicID                       sql.NullString
		acceptedAt, syncedAt           sql.NullTime
		syncURL, syncHandle, syncUser  sql.NullString
		syncToken, pendingTerms        sql.NullString
		pendingItems                   []byte
	)
	if err := row.Scan(&id, &tenantID, &p.Name, &p.Platform, &p.Handle, &p.ProgramURL, &status, &p.ScopeSource,
		&p.Authoritative, &rules, &items, &p.TermsSHA256, &acceptedBy, &acceptedAt, &groupID,
		&createdBy, &p.CreatedAt, &p.UpdatedAt, &vis, &p.TermsText, &publicID,
		&syncURL, &syncHandle, &syncUser, &syncToken, &syncedAt, &p.Sync.LastError, &pendingTerms, &pendingItems); err != nil {
		return nil, err
	}
	p.Sync.URL, p.Sync.Handle, p.Sync.Username, p.Sync.TokenEncrypted = syncURL.String, syncHandle.String, syncUser.String, syncToken.String
	if syncedAt.Valid {
		t := syncedAt.Time
		p.Sync.LastSyncedAt = &t
	}
	if pendingTerms.Valid {
		p.Pending = &bountyprogram.PendingTerms{TermsSHA256: pendingTerms.String}
		if err := json.Unmarshal(pendingItems, &p.Pending.Items); err != nil {
			return nil, fmt.Errorf("decode pending items: %w", err)
		}
	}
	p.ID, _ = shared.IDFromString(id)
	p.TenantID, _ = shared.IDFromString(tenantID)
	p.Status = bountyprogram.Status(status)
	p.Visibility = bountyprogram.Visibility(vis)
	if err := json.Unmarshal(rules, &p.Rules); err != nil {
		return nil, fmt.Errorf("decode program rules: %w", err)
	}
	if err := json.Unmarshal(items, &p.ScopeItems); err != nil {
		return nil, fmt.Errorf("decode program items: %w", err)
	}
	p.AcceptedBy, p.GroupID, p.CreatedBy = idPtr(acceptedBy), idPtr(groupID), idPtr(createdBy)
	p.PublicProgramID = idPtr(publicID)
	if acceptedAt.Valid {
		t := acceptedAt.Time
		p.AcceptedAt = &t
	}
	return &p, nil
}

// Entries lists a program's scope entries.
func (r *BountyProgramRepository) Entries(ctx context.Context, tenantID, programID shared.ID) ([]*scope.Target, error) {
	rows, err := r.db.QueryContext(ctx, scopeTargetSelectQuery+` WHERE tenant_id = $1 AND program_id = $2 ORDER BY pattern`,
		tenantID.String(), programID.String())
	if err != nil {
		return nil, fmt.Errorf("list program entries: %w", err)
	}
	defer rows.Close()
	var out []*scope.Target
	for rows.Next() {
		t, err := r.targets.scanTarget(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// TenantEntries lists every scope entry of the tenant (bounded).
func (r *BountyProgramRepository) TenantEntries(ctx context.Context, tenantID shared.ID) ([]*scope.Target, error) {
	rows, err := r.db.QueryContext(ctx, scopeTargetSelectQuery+` WHERE tenant_id = $1 ORDER BY created_at LIMIT 20000`, tenantID.String())
	if err != nil {
		return nil, fmt.Errorf("list scope entries: %w", err)
	}
	defer rows.Close()
	var out []*scope.Target
	for rows.Next() {
		t, err := r.targets.scanTarget(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// Exclusions lists program exclusions (one program, or all of the tenant).
func (r *BountyProgramRepository) Exclusions(ctx context.Context, tenantID shared.ID, programID *shared.ID) ([]bountyprogram.Exclusion, error) {
	q := `SELECT id, tenant_id, program_id, target_type, pattern, reason, created_at
	      FROM bounty_program_exclusions WHERE tenant_id = $1`
	args := []any{tenantID.String()}
	if programID != nil {
		q += ` AND program_id = $2`
		args = append(args, programID.String())
	}
	q += ` ORDER BY pattern LIMIT 10000`
	rows, err := r.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("list program exclusions: %w", err)
	}
	defer rows.Close()
	var out []bountyprogram.Exclusion
	for rows.Next() {
		var (
			e                 bountyprogram.Exclusion
			id, tid, pid, typ string
			createdAt         time.Time
		)
		if err := rows.Scan(&id, &tid, &pid, &typ, &e.Pattern, &e.Reason, &createdAt); err != nil {
			return nil, err
		}
		e.ID, _ = shared.IDFromString(id)
		e.TenantID, _ = shared.IDFromString(tid)
		e.ProgramID, _ = shared.IDFromString(pid)
		e.TargetType, e.CreatedAt = scope.TargetType(typ), createdAt
		out = append(out, e)
	}
	return out, rows.Err()
}

// IsMember reports whether the user is in the program's active group.
func (r *BountyProgramRepository) IsMember(ctx context.Context, tenantID, programID, userID shared.ID) (bool, error) {
	var ok bool
	err := r.db.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM bounty_programs p
			JOIN groups g ON g.tenant_id = p.tenant_id AND g.id = p.group_id AND g.is_active
			JOIN group_members gm ON gm.group_id = g.id
			WHERE p.tenant_id = $1 AND p.id = $2 AND gm.user_id = $3)`,
		tenantID.String(), programID.String(), userID.String()).Scan(&ok)
	if err != nil {
		return false, fmt.Errorf("program membership: %w", err)
	}
	return ok, nil
}

// MemberProgramIDs lists the programs whose active group has the user.
func (r *BountyProgramRepository) MemberProgramIDs(ctx context.Context, tenantID, userID shared.ID) ([]shared.ID, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT p.id FROM bounty_programs p
		JOIN groups g ON g.tenant_id = p.tenant_id AND g.id = p.group_id AND g.is_active
		JOIN group_members gm ON gm.group_id = g.id
		WHERE p.tenant_id = $1 AND gm.user_id = $2`, tenantID.String(), userID.String())
	if err != nil {
		return nil, fmt.Errorf("program memberships: %w", err)
	}
	defer rows.Close()
	var out []shared.ID
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		if id, err := shared.IDFromString(s); err == nil {
			out = append(out, id)
		}
	}
	return out, rows.Err()
}

// visibilityOf is the stored visibility; a program without one is private.
func visibilityOf(p *bountyprogram.Program) string {
	if p.Visibility == bountyprogram.VisibilityPublic {
		return string(bountyprogram.VisibilityPublic)
	}
	return string(bountyprogram.VisibilityPrivate)
}

// Attest records that a person accepted a program's terms (RFC-065 §15.3).
func (r *BountyProgramRepository) Attest(ctx context.Context, a bountyprogram.Attestation) error {
	res, err := r.db.ExecContext(ctx, `
		INSERT INTO bounty_program_attestations (tenant_id, program_id, user_id, terms_sha256, accepted_at)
		SELECT p.tenant_id, p.id, $3, $4, $5 FROM bounty_programs p WHERE p.tenant_id = $1 AND p.id = $2
		ON CONFLICT (tenant_id, program_id, user_id)
		DO UPDATE SET terms_sha256 = EXCLUDED.terms_sha256, accepted_at = EXCLUDED.accepted_at`,
		a.TenantID.String(), a.ProgramID.String(), a.UserID.String(), a.TermsSHA256, a.AcceptedAt)
	if err != nil {
		return fmt.Errorf("record attestation: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return bountyprogram.ErrNotFound
	}
	return nil
}

// Attestations returns the terms hash each program of the tenant was last
// accepted at by the user.
func (r *BountyProgramRepository) Attestations(ctx context.Context, tenantID, userID shared.ID) (map[shared.ID]string, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT program_id, terms_sha256 FROM bounty_program_attestations
		WHERE tenant_id = $1 AND user_id = $2`, tenantID.String(), userID.String())
	if err != nil {
		return nil, fmt.Errorf("list attestations: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[shared.ID]string{}
	for rows.Next() {
		var pid, sum string
		if err := rows.Scan(&pid, &sum); err != nil {
			return nil, err
		}
		id, err := shared.IDFromString(pid)
		if err != nil {
			continue
		}
		out[id] = sum
	}
	return out, rows.Err()
}

// PrivateProgramIDs lists the tenant's private programs.
func (r *BountyProgramRepository) PrivateProgramIDs(ctx context.Context, tenantID shared.ID) ([]shared.ID, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id FROM bounty_programs WHERE tenant_id = $1 AND visibility = 'private'`, tenantID.String())
	if err != nil {
		return nil, fmt.Errorf("list private programs: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []shared.ID
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		if id, err := shared.IDFromString(s); err == nil {
			out = append(out, id)
		}
	}
	return out, rows.Err()
}
