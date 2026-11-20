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

// Card event kinds in the vulnerability event log (the vuln id is the card id).
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

// AppliedFile (see advisory.Store).
func (r *AdvisoryCardRepository) AppliedFile(ctx context.Context) (string, error) {
	var sum string
	err := r.db.QueryRowContext(ctx, `SELECT file_sha256 FROM advisory_card_stream WHERE singleton`).Scan(&sum)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("cards stream: %w", err)
	}
	return sum, nil
}

// Apply (see advisory.Store).
//
//nolint:cyclop,gocognit // one transaction, one branch per card change
func (r *AdvisoryCardRepository) Apply(ctx context.Context, cards []*advisory.Card, stream advisory.StreamApplied, now time.Time) (advisory.Applied, error) {
	sequence := stream.Sequence
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
		if exists && !advisory.Supersedes(revision, state, c) {
			// Same, older, or a same-revision change other than a
			// withdrawal: a replayed or unchecked stream never rolls a card
			// back nor brings a withdrawn one back.
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
			c.ID, c.Revision, c.Title, c.Severity.Level, c.Exploitation.Status, c.Review.State, nullStr(c.Review.Mode), body,
			c.PublishedAt, c.UpdatedAt, nullTime(c.Review.ReviewedAt), seq, now); err != nil {
			return res, fmt.Errorf("card %s: %w", c.ID, err)
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO advisory_card_revisions (card_id, revision, review_state, body, imported_at) VALUES ($1, $2, $3, $4, $5)
			ON CONFLICT (card_id, revision, review_state) DO NOTHING`,
			c.ID, c.Revision, c.Review.State, body, now); err != nil {
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
		src, seqNo := c.UpdatedAt, seq
		if err := insertVulnEvents(ctx, tx, []vulnevent.Event{{VulnID: c.ID, Kind: kind, At: now, SourceAt: &src, FeedSequence: &seqNo,
			Detail: map[string]any{"revision": c.Revision, "exploitation": c.Exploitation.Status,
				"vulns": len(c.Vulns), "review_mode": c.Review.Mode}}}); err != nil {
			return res, fmt.Errorf("card %s event: %w", c.ID, err)
		}
	}
	if stream.FileSHA256 != "" {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO advisory_card_stream (singleton, file_sha256, feed_sequence, as_of, applied_at) VALUES (true, $1, $2, $3, $4)
			ON CONFLICT (singleton) DO UPDATE SET file_sha256 = EXCLUDED.file_sha256, feed_sequence = EXCLUDED.feed_sequence,
				as_of = EXCLUDED.as_of, applied_at = EXCLUDED.applied_at`,
			stream.FileSHA256, seq, stream.AsOf, now); err != nil {
			return res, fmt.Errorf("cards stream: %w", err)
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
