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

const publicProgramColumns = `id, feed_id, source, platform, handle, name, program_url, program_type, status,
	offers_bounty, scope_published, scope_items, rules, terms_text, terms_url, terms_doc_sha256,
	content_sha256, as_of, removed_at, feed_sequence, updated_at, provenance`

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
	content string
	removed bool
}

func readCatalogRows(ctx context.Context, tx *sql.Tx) (map[string]publicCatalogRow, error) {
	rows, err := tx.QueryContext(ctx, `SELECT feed_id, id, content_sha256, removed_at IS NOT NULL FROM public_programs`)
	if err != nil {
		return nil, fmt.Errorf("read catalog: %w", err)
	}
	defer func() { _ = rows.Close() }()
	existing := map[string]publicCatalogRow{}
	for rows.Next() {
		var feedID string
		var c publicCatalogRow
		if err := rows.Scan(&feedID, &c.id, &c.content, &c.removed); err != nil {
			return nil, err
		}
		existing[feedID] = c
	}
	return existing, rows.Err()
}

func bounded(v uint64) int64 { return int64(min(v, 1<<62)) } //nolint:gosec // bounded

// Apply writes a verified snapshot or delta in one transaction.
//
//nolint:cyclop // one branch per change kind
func (r *PublicProgramRepository) Apply(ctx context.Context, a bountyprogram.FeedApply) ([]bountyprogram.CatalogChange, error) {
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
	case uint64(max(applied, 0)) >= a.State.AppliedSequence: //nolint:gosec // non-negative
		return nil, fmt.Errorf("program feed sequence %d is not newer than %d", a.State.AppliedSequence, applied)
	}
	existing, err := readCatalogRows(ctx, tx)
	if err != nil {
		return nil, err
	}
	changes := []bountyprogram.CatalogChange{}
	seen := make(map[string]bool, len(a.Programs))
	for i := range a.Programs {
		p := &a.Programs[i]
		seen[p.FeedID] = true
		items, err := json.Marshal(p.Items)
		if err != nil {
			return nil, err
		}
		rules, err := json.Marshal(p.Rules)
		if err != nil {
			return nil, err
		}
		prov, err := json.Marshal(p.Provenance)
		if err != nil {
			return nil, err
		}
		var id string
		if err := tx.QueryRowContext(ctx, `
			INSERT INTO public_programs (feed_id, source, platform, handle, name, program_url, program_type, status,
			       offers_bounty, scope_published, scope_items, rules, terms_text, terms_url, terms_doc_sha256,
			       content_sha256, as_of, removed_at, feed_sequence, updated_at, provenance)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, NULL, $18, now(), $19)
			ON CONFLICT (feed_id) DO UPDATE SET source = EXCLUDED.source, platform = EXCLUDED.platform,
			       handle = EXCLUDED.handle, name = EXCLUDED.name, program_url = EXCLUDED.program_url,
			       program_type = EXCLUDED.program_type, status = EXCLUDED.status, offers_bounty = EXCLUDED.offers_bounty,
			       scope_published = EXCLUDED.scope_published, scope_items = EXCLUDED.scope_items, rules = EXCLUDED.rules,
			       terms_text = EXCLUDED.terms_text, terms_url = EXCLUDED.terms_url,
			       terms_doc_sha256 = EXCLUDED.terms_doc_sha256, content_sha256 = EXCLUDED.content_sha256,
			       as_of = EXCLUDED.as_of, removed_at = NULL, feed_sequence = EXCLUDED.feed_sequence, updated_at = now(),
			       provenance = EXCLUDED.provenance
			RETURNING id`,
			p.FeedID, p.Source, p.Platform, p.Handle, p.Name, p.URL, p.Type, p.Status, p.OffersBounty, p.ScopePublished,
			items, rules, p.TermsText, p.TermsURL, p.TermsDocSHA256, p.TermsSHA256, p.AsOf, bounded(p.Sequence), prov).Scan(&id); err != nil {
			return nil, fmt.Errorf("upsert %s: %w", p.FeedID, err)
		}
		p.ID, _ = shared.IDFromString(id)
		old, had := existing[p.FeedID]
		switch {
		case !had || old.removed:
			changes = append(changes, bountyprogram.CatalogChange{ProgramID: p.ID, FeedID: p.FeedID, Kind: bountyprogram.ChangeAdded})
		case old.content != p.TermsSHA256:
			changes = append(changes, bountyprogram.CatalogChange{ProgramID: p.ID, FeedID: p.FeedID, Kind: bountyprogram.ChangeChanged})
		}
	}
	// Archived: missing from a snapshot, or dropped by a delta.
	archive := []string{}
	if a.Snapshot {
		for feedID, c := range existing {
			if !seen[feedID] && !c.removed {
				archive = append(archive, feedID)
			}
		}
	} else {
		for _, feedID := range a.Dropped {
			if c, ok := existing[feedID]; ok && !c.removed && !seen[feedID] {
				archive = append(archive, feedID)
			}
		}
	}
	for _, feedID := range archive {
		id, _ := shared.IDFromString(existing[feedID].id)
		changes = append(changes, bountyprogram.CatalogChange{ProgramID: id, FeedID: feedID, Kind: bountyprogram.ChangeRemoved})
	}
	if len(archive) > 0 {
		if _, err := tx.ExecContext(ctx, `UPDATE public_programs SET removed_at = now(), updated_at = now() WHERE feed_id = ANY($1)`,
			pq.StringArray(archive)); err != nil {
			return nil, fmt.Errorf("archive programs: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO program_feed_state (id, applied_sequence, keyset_version, applied_at) VALUES (1, $1, $2, now())
		ON CONFLICT (id) DO UPDATE SET applied_sequence = EXCLUDED.applied_sequence,
		       keyset_version = GREATEST(program_feed_state.keyset_version, EXCLUDED.keyset_version), applied_at = now()`,
		bounded(a.State.AppliedSequence), bounded(a.State.KeySetVersion)); err != nil {
		return nil, fmt.Errorf("record program feed state: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return changes, nil
}

func scanPublicProgram(row interface{ Scan(...any) error }) (*bountyprogram.PublicProgram, error) {
	var (
		p                  bountyprogram.PublicProgram
		id                 string
		items, rules, prov []byte
		removed            sql.NullTime
		seq                int64
	)
	if err := row.Scan(&id, &p.FeedID, &p.Source, &p.Platform, &p.Handle, &p.Name, &p.URL, &p.Type, &p.Status,
		&p.OffersBounty, &p.ScopePublished, &items, &rules, &p.TermsText, &p.TermsURL, &p.TermsDocSHA256,
		&p.TermsSHA256, &p.AsOf, &removed, &seq, &p.UpdatedAt, &prov); err != nil {
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
	if err := json.Unmarshal(prov, &p.Provenance); err != nil {
		return nil, fmt.Errorf("decode provenance: %w", err)
	}
	return &p, nil
}

// ListPublic lists published (not archived) programs, open ones first.
func (r *PublicProgramRepository) ListPublic(ctx context.Context, search string, limit, offset int) ([]bountyprogram.PublicProgram, int, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	where := `removed_at IS NULL`
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
	q := fmt.Sprintf(`SELECT %s FROM public_programs WHERE %s ORDER BY (status = 'open') DESC, lower(name), feed_id LIMIT $%d OFFSET $%d`,
		publicProgramColumns, where, len(args)-1, len(args))
	rows, err := r.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list catalog: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := make([]bountyprogram.PublicProgram, 0, 16)
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

// StaleSubscriptions lists followed programs whose catalog program changed
// since they were brought up to date, or that are still active while it is
// closed, paused or archived (system pass across tenants; each program is
// then handled in its own tenant).
func (r *PublicProgramRepository) StaleSubscriptions(ctx context.Context, limit int) ([]bountyprogram.ProgramRef, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT b.tenant_id, b.id FROM bounty_programs b
		JOIN public_programs p ON p.id = b.public_program_id
		WHERE b.status <> 'ended'
		  AND (b.public_synced_sha256 <> p.content_sha256
		       OR (b.status = 'active' AND (p.removed_at IS NOT NULL OR p.status <> 'open')))
		ORDER BY b.updated_at LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("list stale subscriptions: %w", err)
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
