package postgres

// Chunked program feed import (docs/architecture/feed-transfer.md):
// each verified chunk is applied in its own transaction together with the
// feed checkpoint, and the bundle is finished by CompleteFeedBundle. The
// catalog is platform-wide public data: nothing here is tenant-scoped and
// nothing tenant-specific is written.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/lib/pq"
	"github.com/openctemio/sdk-go/pkg/transfer/bundle"

	"github.com/openctemio/openctem/api/pkg/domain/bountyprogram"
)

// feedOfStream is the checkpoint row of a program feed stream.
func feedOfStream(stream string) string {
	if stream == bountyprogram.StreamLocal {
		return FeedProgramFeedLocal
	}
	return FeedProgramFeed
}

func normStream(stream string) string {
	if stream == bountyprogram.StreamLocal {
		return bountyprogram.StreamLocal
	}
	return bountyprogram.StreamSigned
}

// FeedCheckpoint returns the checkpoint of a program feed stream.
func (r *PublicProgramRepository) FeedCheckpoint(stream string) bundle.Checkpoint {
	return r.feedCheckpoint(stream)
}

func (r *PublicProgramRepository) feedCheckpoint(stream string) *FeedCheckpoint {
	return &FeedCheckpoint{db: r.db, feed: feedOfStream(stream)}
}

// upsertChunkProgram writes one program unless the stored record must win:
// a record of a newer sequence of the same stream (a replayed or abandoned
// chunk never replaces it), or a live signed record when the local stream
// writes. It reports whether the row was written.
func upsertChunkProgram(ctx context.Context, tx *sql.Tx, p *bountyprogram.PublicProgram, stream string) (bool, error) {
	items, err := json.Marshal(p.Items)
	if err != nil {
		return false, err
	}
	rules, err := json.Marshal(p.Rules)
	if err != nil {
		return false, err
	}
	prov, err := json.Marshal(p.Provenance)
	if err != nil {
		return false, err
	}
	res, err := tx.ExecContext(ctx, `
		INSERT INTO public_programs (feed_id, source, platform, handle, name, program_url, program_type, status,
		       offers_bounty, scope_published, scope_items, rules, terms_text, terms_url, terms_doc_sha256,
		       content_sha256, as_of, removed_at, feed_sequence, updated_at, provenance, feed_stream)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, NULL, $18, now(), $19, $20)
		ON CONFLICT (feed_id) DO UPDATE SET source = EXCLUDED.source, platform = EXCLUDED.platform,
		       handle = EXCLUDED.handle, name = EXCLUDED.name, program_url = EXCLUDED.program_url,
		       program_type = EXCLUDED.program_type, status = EXCLUDED.status, offers_bounty = EXCLUDED.offers_bounty,
		       scope_published = EXCLUDED.scope_published, scope_items = EXCLUDED.scope_items, rules = EXCLUDED.rules,
		       terms_text = EXCLUDED.terms_text, terms_url = EXCLUDED.terms_url,
		       terms_doc_sha256 = EXCLUDED.terms_doc_sha256, content_sha256 = EXCLUDED.content_sha256,
		       as_of = EXCLUDED.as_of, removed_at = NULL, feed_sequence = EXCLUDED.feed_sequence, updated_at = now(),
		       provenance = EXCLUDED.provenance, feed_stream = EXCLUDED.feed_stream
		WHERE (public_programs.feed_stream = EXCLUDED.feed_stream AND public_programs.feed_sequence <= EXCLUDED.feed_sequence)
		   OR (public_programs.feed_stream <> EXCLUDED.feed_stream
		       AND (EXCLUDED.feed_stream = 'signed' OR public_programs.removed_at IS NOT NULL))`,
		p.FeedID, p.Source, p.Platform, p.Handle, p.Name, p.URL, p.Type, p.Status, p.OffersBounty, p.ScopePublished,
		items, rules, p.TermsText, p.TermsURL, p.TermsDocSHA256, p.TermsSHA256, p.AsOf, bounded(p.Sequence), prov, stream)
	if err != nil {
		return false, fmt.Errorf("upsert %s: %w", p.FeedID, err)
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

func distinct(ids []string) []string {
	seen := make(map[string]bool, len(ids))
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}

// ApplyFeedChunk applies one verified chunk and advances the checkpoint to
// next in the same transaction (exactly once: a chunk whose transaction
// committed is never applied again, and two runs never both apply one).
// It returns the number of programs written.
//
//nolint:cyclop // one refusal per contract rule
func (r *PublicProgramRepository) ApplyFeedChunk(ctx context.Context, c bountyprogram.FeedChunk, next bundle.State) (int, error) {
	stream := normStream(c.Stream)
	if c.Sequence == 0 || c.Sequence != next.InProgress {
		return 0, fmt.Errorf("chunk sequence %d is not the bundle in progress %d", c.Sequence, next.InProgress)
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := r.feedCheckpoint(stream).AdvanceTx(ctx, tx, next); err != nil {
		return 0, err
	}
	written := 0
	for i := range c.Programs {
		p := &c.Programs[i]
		if p.Sequence != c.Sequence {
			return 0, fmt.Errorf("program %s has sequence %d, the bundle is %d", p.FeedID, p.Sequence, c.Sequence)
		}
		ok, err := upsertChunkProgram(ctx, tx, p, stream)
		if err != nil {
			return 0, err
		}
		if ok {
			written++
		}
	}
	seq := bounded(c.Sequence)
	if listed := distinct(c.Listed); len(listed) > 0 {
		var n int
		if err := tx.QueryRowContext(ctx, `
			SELECT count(*) FROM public_programs
			WHERE feed_id = ANY($1) AND removed_at IS NULL
			  AND ((feed_stream = $2 AND feed_sequence >= $3) OR ($2 = 'local' AND feed_stream = 'signed'))`,
			pq.StringArray(listed), stream, seq).Scan(&n); err != nil {
			return 0, fmt.Errorf("check changed programs: %w", err)
		}
		if n != len(listed) {
			return 0, errors.New("a change names a program the bundle does not hold")
		}
	}
	if dropped := distinct(c.Dropped); len(dropped) > 0 {
		var n int
		if err := tx.QueryRowContext(ctx, `
			SELECT count(*) FROM public_programs WHERE feed_id = ANY($1) AND feed_stream = $2 AND feed_sequence = $3`,
			pq.StringArray(dropped), stream, seq).Scan(&n); err != nil {
			return 0, fmt.Errorf("check dropped programs: %w", err)
		}
		if n != 0 {
			return 0, errors.New("a dropped program is held by the same bundle")
		}
		if _, err := tx.ExecContext(ctx, `
			UPDATE public_programs SET removed_at = now(), updated_at = now()
			WHERE feed_id = ANY($1) AND feed_stream = $2 AND feed_sequence < $3 AND removed_at IS NULL`,
			pq.StringArray(dropped), stream, seq); err != nil {
			return 0, fmt.Errorf("archive dropped programs: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return written, nil
}

// CompleteFeedBundle finishes a chunked bundle: a snapshot archives the
// stream's programs it did not hold (older sequence), and the applied
// sequence and key-set version are recorded in program_feed_state and the
// checkpoint, in one transaction. A sequence not newer than the applied
// one is refused.
func (r *PublicProgramRepository) CompleteFeedBundle(ctx context.Context, c bountyprogram.FeedComplete, done bundle.State) error {
	stream := normStream(c.Stream)
	if c.State.AppliedSequence == 0 || c.State.AppliedSequence != done.Applied {
		return fmt.Errorf("complete sequence %d does not match the checkpoint %d", c.State.AppliedSequence, done.Applied)
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := r.feedCheckpoint(stream).CompleteTx(ctx, tx, done); err != nil {
		return err
	}
	var applied int64
	err = tx.QueryRowContext(ctx, `SELECT applied_sequence FROM program_feed_state WHERE id = $1 FOR UPDATE`, stateRow(stream)).Scan(&applied)
	switch {
	case errors.Is(err, sql.ErrNoRows):
	case err != nil:
		return fmt.Errorf("lock program feed state: %w", err)
	case uint64(max(applied, 0)) >= c.State.AppliedSequence: //nolint:gosec // non-negative
		return fmt.Errorf("program feed sequence %d is not newer than %d", c.State.AppliedSequence, applied)
	}
	if c.Snapshot {
		if _, err := tx.ExecContext(ctx, `
			UPDATE public_programs SET removed_at = now(), updated_at = now()
			WHERE feed_stream = $1 AND feed_sequence < $2 AND removed_at IS NULL`,
			stream, bounded(c.State.AppliedSequence)); err != nil {
			return fmt.Errorf("archive programs: %w", err)
		}
	}
	if err := recordFeedState(ctx, tx, stream, c.State); err != nil {
		return err
	}
	return tx.Commit()
}

func recordFeedState(ctx context.Context, tx *sql.Tx, stream string, st bountyprogram.FeedState) error {
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO program_feed_state (id, applied_sequence, keyset_version, applied_at) VALUES ($3, $1, $2, now())
		ON CONFLICT (id) DO UPDATE SET applied_sequence = EXCLUDED.applied_sequence,
		       keyset_version = GREATEST(program_feed_state.keyset_version, EXCLUDED.keyset_version), applied_at = now()`,
		bounded(st.AppliedSequence), bounded(st.KeySetVersion), stateRow(stream)); err != nil {
		return fmt.Errorf("record program feed state: %w", err)
	}
	return nil
}
