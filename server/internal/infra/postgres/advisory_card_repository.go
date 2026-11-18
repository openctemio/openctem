package postgres

// Advisory cards from the signed vulnerability bundle (docs/rfcs/RFC-117-
// emerging-threat-alerts.md, "Advisory cards"). Platform-wide public facts:
// no tenant column, written only by the bundle importer, read by the
// emerging-threat planner and the alert detail.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/server/pkg/domain/advisory"
	"github.com/openctemio/openctem/server/pkg/domain/vulnevent"
)

// Card event kinds in vuln_events (the vuln id is the card id).
const (
	CardEventPublished = vulnevent.KindCardPublished
	CardEventUpdated   = vulnevent.KindCardUpdated
	CardEventWithdrawn = vulnevent.KindCardWithdrawn
)

// AdvisoryCardRepository implements advisory.Store.
type AdvisoryCardRepository struct{ db *DB }

// NewAdvisoryCardRepository creates the repository.
func NewAdvisoryCardRepository(db *DB) *AdvisoryCardRepository {
	return &AdvisoryCardRepository{db: db}
}

var _ advisory.Store = (*AdvisoryCardRepository)(nil)

// AsOf (see advisory.Store).
func (r *AdvisoryCardRepository) AsOf(ctx context.Context) (time.Time, error) {
	var t sql.NullTime
	if err := r.db.QueryRowContext(ctx, `SELECT max(GREATEST(updated_at, reviewed_at)) FROM advisory_cards`).Scan(&t); err != nil {
		return time.Time{}, fmt.Errorf("cards as of: %w", err)
	}
	return t.Time, nil
}

// Apply (see advisory.Store).
//
//nolint:cyclop // one transaction, one branch per card change
func (r *AdvisoryCardRepository) Apply(ctx context.Context, cards []*advisory.Card, sequence uint64, now time.Time) (advisory.Applied, error) {
	var res advisory.Applied
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return res, err
	}
	defer func() { _ = tx.Rollback() }()
	seq := int64(0)
	if sequence <= uint64(1<<62) {
		seq = int64(sequence)
	}
	for _, c := range cards {
		var revision int
		var state string
		err := tx.QueryRowContext(ctx, `SELECT revision, review_state FROM advisory_cards WHERE card_id = $1 FOR UPDATE`, c.ID).Scan(&revision, &state)
		exists := err == nil
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return res, fmt.Errorf("card %s: %w", c.ID, err)
		}
		if exists && (c.Revision < revision || (c.Revision == revision && c.Review.State == state)) {
			// Same or older: a replayed stream never rolls a card back.
			res.Unchanged++
			continue
		}
		body, err := json.Marshal(c)
		if err != nil {
			return res, err
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO advisory_cards (card_id, revision, title, severity, exploitation, review_state, review_mode, body,
				published_at, updated_at, reviewed_at, feed_sequence, first_seen_at, imported_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $13)
			ON CONFLICT (card_id) DO UPDATE SET revision = EXCLUDED.revision, title = EXCLUDED.title,
				severity = EXCLUDED.severity, exploitation = EXCLUDED.exploitation, review_state = EXCLUDED.review_state,
				review_mode = EXCLUDED.review_mode, body = EXCLUDED.body, published_at = EXCLUDED.published_at,
				updated_at = EXCLUDED.updated_at, reviewed_at = EXCLUDED.reviewed_at,
				feed_sequence = EXCLUDED.feed_sequence, imported_at = EXCLUDED.imported_at`,
			c.ID, c.Revision, c.Title, c.Severity.Level, c.Exploitation.Status, c.Review.State, c.Review.Mode, body,
			c.PublishedAt, c.UpdatedAt, *c.Review.ReviewedAt, seq, now); err != nil {
			return res, fmt.Errorf("card %s: %w", c.ID, err)
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO advisory_card_revisions (card_id, revision, body, imported_at) VALUES ($1, $2, $3, $4)
			ON CONFLICT (card_id, revision) DO UPDATE SET body = EXCLUDED.body, imported_at = EXCLUDED.imported_at`,
			c.ID, c.Revision, body, now); err != nil {
			return res, fmt.Errorf("card %s revision: %w", c.ID, err)
		}
		if err := replaceCardLinks(ctx, tx, c); err != nil {
			return res, err
		}
		kind := CardEventPublished
		switch {
		case c.Withdrawn():
			kind = CardEventWithdrawn
			res.Withdrawn++
		case exists:
			kind = CardEventUpdated
			res.Updated++
		default:
			res.Published++
		}
		detail, _ := json.Marshal(map[string]any{"revision": c.Revision, "exploitation": c.Exploitation.Status,
			"vulns": len(c.Vulns), "review_mode": c.Review.Mode})
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO vuln_events (vuln_id, kind, at, source_at, feed_sequence, detail) VALUES ($1, $2, $3, $4, $5, $6)`,
			c.ID, string(kind), now, c.UpdatedAt, seq, detail); err != nil {
			return res, fmt.Errorf("card %s event: %w", c.ID, err)
		}
	}
	return res, tx.Commit()
}

func replaceCardLinks(ctx context.Context, tx *sql.Tx, c *advisory.Card) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM advisory_card_vulns WHERE card_id = $1`, c.ID); err != nil {
		return fmt.Errorf("card %s vulns: %w", c.ID, err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO advisory_card_vulns (card_id, vuln_id) SELECT $1, unnest($2::text[]) ON CONFLICT DO NOTHING`,
		c.ID, pq.Array(c.VulnIDs())); err != nil {
		return fmt.Errorf("card %s vulns: %w", c.ID, err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM advisory_card_products WHERE card_id = $1`, c.ID); err != nil {
		return fmt.Errorf("card %s products: %w", c.ID, err)
	}
	for _, k := range c.ProductKeys() {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO advisory_card_products (card_id, part, cpe_vendor, cpe_product) VALUES ($1, $2, $3, $4)
			ON CONFLICT DO NOTHING`, c.ID, k.Part, k.Vendor, k.Product); err != nil {
			return fmt.Errorf("card %s products: %w", c.ID, err)
		}
	}
	return nil
}

// ExploitationFor (see advisory.Store).
func (r *AdvisoryCardRepository) ExploitationFor(ctx context.Context, vulnIDs []string) (map[string]advisory.Exploitation, error) {
	return exploitationFor(ctx, r.db, vulnIDs)
}

func exploitationFor(ctx context.Context, db *DB, vulnIDs []string) (map[string]advisory.Exploitation, error) {
	out := map[string]advisory.Exploitation{}
	if len(vulnIDs) == 0 {
		return out, nil
	}
	rows, err := db.QueryContext(ctx, `
		SELECT v.vuln_id, c.exploitation FROM advisory_card_vulns v
		JOIN advisory_cards c ON c.card_id = v.card_id AND c.review_state = 'reviewed'
		WHERE v.vuln_id = ANY($1::text[])`, pq.Array(vulnIDs))
	if err != nil {
		return nil, fmt.Errorf("card exploitation: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id, e string
		if err := rows.Scan(&id, &e); err != nil {
			return nil, err
		}
		out[id] = advisory.Stronger(out[id], advisory.Exploitation(e))
	}
	return out, rows.Err()
}

// Card returns a stored card (nil when unknown).
func (r *AdvisoryCardRepository) Card(ctx context.Context, cardID string) (*advisory.Card, error) {
	return loadCard(ctx, r.db, cardID)
}

func loadCard(ctx context.Context, db *DB, cardID string) (*advisory.Card, error) {
	if !advisory.IsCardID(cardID) {
		return nil, nil
	}
	var body []byte
	err := db.QueryRowContext(ctx, `SELECT body FROM advisory_cards WHERE card_id = $1`, cardID).Scan(&body)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("card %s: %w", cardID, err)
	}
	var c advisory.Card
	if err := json.Unmarshal(body, &c); err != nil {
		return nil, fmt.Errorf("card %s: %w", cardID, err)
	}
	return &c, nil
}
