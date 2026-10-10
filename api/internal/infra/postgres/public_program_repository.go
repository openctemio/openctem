package postgres

// The public program catalog (RFC-065 §16): written only by the program
// feed importer, read by every tenant (public data). Subscriptions are the
// tenant programs that name a catalog program.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/bountyprogram"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// PublicProgramRepository implements bountyprogram.CatalogRepository.
type PublicProgramRepository struct{ db *DB }

var _ bountyprogram.CatalogRepository = (*PublicProgramRepository)(nil)

// NewPublicProgramRepository creates the repository.
func NewPublicProgramRepository(db *DB) *PublicProgramRepository {
	return &PublicProgramRepository{db: db}
}

const publicProgramColumns = `id, feed_id, platform, handle, name, program_url, offers_bounty, open,
	scope_items, rules, terms_text, terms_sha256, source, as_of, removed_at, feed_sequence, updated_at`

// FeedState returns the applied state (zero before the first import).
func (r *PublicProgramRepository) FeedState(ctx context.Context) (bountyprogram.FeedState, error) {
	var st bountyprogram.FeedState
	var at time.Time
	var seq, ver int64
	err := r.db.QueryRowContext(ctx, `SELECT applied_sequence, keyset_version, applied_at FROM program_feed_state WHERE id = 1`).
		Scan(&seq, &ver, &at)
	if errors.Is(err, sql.ErrNoRows) {
		return st, nil
	}
	if err != nil {
		return st, fmt.Errorf("read program feed state: %w", err)
	}
	st.AppliedSequence, st.KeySetVersion, st.AppliedAt = uint64(max(seq, 0)), uint64(max(ver, 0)), &at //nolint:gosec // non-negative
	return st, nil
}

type publicCatalogRow struct {
	id      string
	terms   string
	open    bool
	removed bool
}

// ApplySnapshot replaces the catalog with a verified snapshot.
//
//nolint:cyclop // one branch per change kind
func (r *PublicProgramRepository) ApplySnapshot(ctx context.Context, st bountyprogram.FeedState, programs []bountyprogram.PublicProgram) ([]bountyprogram.CatalogChange, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// The state row serializes importers and refuses an older bundle.
	var applied int64
	err = tx.QueryRowContext(ctx, `SELECT applied_sequence FROM program_feed_state WHERE id = 1 FOR UPDATE`).Scan(&applied)
	switch {
	case errors.Is(err, sql.ErrNoRows):
	case err != nil:
		return nil, fmt.Errorf("lock program feed state: %w", err)
	case uint64(max(applied, 0)) >= st.AppliedSequence: //nolint:gosec // non-negative
		return nil, fmt.Errorf("program feed sequence %d is not newer than %d", st.AppliedSequence, applied)
	}

	existing, err := readCatalogRows(ctx, tx)
	if err != nil {
		return nil, err
	}

	changes := []bountyprogram.CatalogChange{}
	seen := make(map[string]bool, len(programs))
	for i := range programs {
		p := &programs[i]
		seen[p.FeedID] = true
		items, err := json.Marshal(p.Items)
		if err != nil {
			return nil, err
		}
		rules, err := json.Marshal(p.Rules)
		if err != nil {
			return nil, err
		}
		var id string
		if err := tx.QueryRowContext(ctx, `
			INSERT INTO public_programs (feed_id, platform, handle, name, program_url, offers_bounty, open,
			       scope_items, rules, terms_text, terms_sha256, source, as_of, removed_at, feed_sequence, updated_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, NULL, $14, now())
			ON CONFLICT (feed_id) DO UPDATE SET platform = EXCLUDED.platform, handle = EXCLUDED.handle,
			       name = EXCLUDED.name, program_url = EXCLUDED.program_url, offers_bounty = EXCLUDED.offers_bounty,
			       open = EXCLUDED.open, scope_items = EXCLUDED.scope_items, rules = EXCLUDED.rules,
			       terms_text = EXCLUDED.terms_text, terms_sha256 = EXCLUDED.terms_sha256, source = EXCLUDED.source,
			       as_of = EXCLUDED.as_of, removed_at = NULL, feed_sequence = EXCLUDED.feed_sequence, updated_at = now()
			RETURNING id`,
			p.FeedID, p.Platform, p.Handle, p.Name, p.URL, p.OffersBounty, p.Open, items, rules, p.TermsText,
			p.TermsSHA256, p.Source, p.AsOf, int64(min(p.Sequence, 1<<62))).Scan(&id); err != nil { //nolint:gosec // bounded
			return nil, fmt.Errorf("upsert %s: %w", p.FeedID, err)
		}
		p.ID, _ = shared.IDFromString(id)
		old, had := existing[p.FeedID]
		switch {
		case !had || old.removed:
			changes = append(changes, bountyprogram.CatalogChange{ProgramID: p.ID, FeedID: p.FeedID, Kind: bountyprogram.ChangeAdded})
		case old.open && !p.Open:
			changes = append(changes, bountyprogram.CatalogChange{ProgramID: p.ID, FeedID: p.FeedID, Kind: bountyprogram.ChangeClosed})
		case old.terms != p.TermsSHA256 || old.open != p.Open:
			changes = append(changes, bountyprogram.CatalogChange{ProgramID: p.ID, FeedID: p.FeedID, Kind: bountyprogram.ChangeChanged})
		}
	}
	var gone []string
	for feedID, c := range existing {
		if !seen[feedID] && !c.removed {
			gone = append(gone, feedID)
			id, _ := shared.IDFromString(c.id)
			changes = append(changes, bountyprogram.CatalogChange{ProgramID: id, FeedID: feedID, Kind: bountyprogram.ChangeRemoved})
		}
	}
	if len(gone) > 0 {
		if _, err := tx.ExecContext(ctx, `UPDATE public_programs SET removed_at = now(), updated_at = now() WHERE feed_id = ANY($1)`,
			pq.StringArray(gone)); err != nil {
			return nil, fmt.Errorf("mark removed: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO program_feed_state (id, applied_sequence, keyset_version, applied_at) VALUES (1, $1, $2, now())
		ON CONFLICT (id) DO UPDATE SET applied_sequence = EXCLUDED.applied_sequence,
		       keyset_version = GREATEST(program_feed_state.keyset_version, EXCLUDED.keyset_version), applied_at = now()`,
		int64(min(st.AppliedSequence, 1<<62)), int64(min(st.KeySetVersion, 1<<62))); err != nil { //nolint:gosec // bounded
		return nil, fmt.Errorf("record program feed state: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return changes, nil
}

func readCatalogRows(ctx context.Context, tx *sql.Tx) (map[string]publicCatalogRow, error) {
	rows, err := tx.QueryContext(ctx, `SELECT feed_id, id, terms_sha256, open, removed_at IS NOT NULL FROM public_programs`)
	if err != nil {
		return nil, fmt.Errorf("read catalog: %w", err)
	}
	defer func() { _ = rows.Close() }()
	existing := map[string]publicCatalogRow{}
	for rows.Next() {
		var feedID string
		var c publicCatalogRow
		if err := rows.Scan(&feedID, &c.id, &c.terms, &c.open, &c.removed); err != nil {
			return nil, err
		}
		existing[feedID] = c
	}
	return existing, rows.Err()
}

func scanPublicProgram(row interface{ Scan(...any) error }) (*bountyprogram.PublicProgram, error) {
	var (
		p            bountyprogram.PublicProgram
		id           string
		items, rules []byte
		removed      sql.NullTime
		seq          int64
	)
	if err := row.Scan(&id, &p.FeedID, &p.Platform, &p.Handle, &p.Name, &p.URL, &p.OffersBounty, &p.Open,
		&items, &rules, &p.TermsText, &p.TermsSHA256, &p.Source, &p.AsOf, &removed, &seq, &p.UpdatedAt); err != nil {
		return nil, err
	}
	p.ID, _ = shared.IDFromString(id)
	p.Sequence = uint64(max(seq, 0)) //nolint:gosec // non-negative
	if removed.Valid {
		t := removed.Time
		p.RemovedAt = &t
	}
	if err := json.Unmarshal(items, &p.Items); err != nil {
		return nil, fmt.Errorf("decode items: %w", err)
	}
	if err := json.Unmarshal(rules, &p.Rules); err != nil {
		return nil, fmt.Errorf("decode rules: %w", err)
	}
	return &p, nil
}

// ListPublic lists open, published programs by name.
func (r *PublicProgramRepository) ListPublic(ctx context.Context, search string, limit, offset int) ([]bountyprogram.PublicProgram, int, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	where := `removed_at IS NULL AND open`
	args := []any{}
	if search != "" {
		where += ` AND (name ILIKE $1 OR feed_id ILIKE $1)`
		args = append(args, wrapLikePattern(search))
	}
	var total int
	if err := r.db.QueryRowContext(ctx, `SELECT count(*) FROM public_programs WHERE `+where, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count catalog: %w", err)
	}
	args = append(args, limit, max(offset, 0))
	q := fmt.Sprintf(`SELECT %s FROM public_programs WHERE %s ORDER BY lower(name), feed_id LIMIT $%d OFFSET $%d`,
		publicProgramColumns, where, len(args)-1, len(args))
	rows, err := r.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list catalog: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := make([]bountyprogram.PublicProgram, 0, limit)
	for rows.Next() {
		p, err := scanPublicProgram(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, *p)
	}
	return out, total, rows.Err()
}

// GetPublic returns one catalog program.
func (r *PublicProgramRepository) GetPublic(ctx context.Context, id shared.ID) (*bountyprogram.PublicProgram, error) {
	p, err := scanPublicProgram(r.db.QueryRowContext(ctx, `SELECT `+publicProgramColumns+` FROM public_programs WHERE id = $1`, id.String()))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, bountyprogram.ErrNotFound
	}
	return p, err
}

// StaleSubscriptions lists subscribed programs that differ from their
// catalog program (system pass across tenants; each program is then
// handled in its own tenant).
func (r *PublicProgramRepository) StaleSubscriptions(ctx context.Context, limit int) ([]bountyprogram.ProgramRef, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT b.tenant_id, b.id FROM bounty_programs b
		JOIN public_programs p ON p.id = b.public_program_id
		WHERE b.status <> 'ended'
		  AND (b.terms_sha256 <> p.terms_sha256
		       OR (b.status = 'active' AND (p.removed_at IS NOT NULL OR NOT p.open)))
		ORDER BY b.updated_at LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("list subscribers: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []bountyprogram.ProgramRef
	for rows.Next() {
		var t, p string
		if err := rows.Scan(&t, &p); err != nil {
			return nil, err
		}
		tid, err1 := shared.IDFromString(t)
		pid, err2 := shared.IDFromString(p)
		if err1 == nil && err2 == nil {
			out = append(out, bountyprogram.ProgramRef{TenantID: tid, ProgramID: pid})
		}
	}
	return out, rows.Err()
}
