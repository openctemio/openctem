package postgres

// Durable progress of the chunked feed importers
// (docs/architecture/feed-transfer.md): one feed_checkpoints row per feed.
// Feed data is platform-wide catalog data; the table has no tenant column
// and nothing tenant-specific is ever written through it.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/openctemio/sdk-go/pkg/transfer/bundle"
)

// Feed checkpoint rows.
const (
	FeedProgramFeed      = "programfeed"
	FeedProgramFeedLocal = "programfeed-local"
	FeedVulnFeed         = "vulnfeed"
)

// ErrCheckpointMoved: the stored checkpoint is not the one this run
// continues (another run advanced it, or a newer sequence was applied).
var ErrCheckpointMoved = errors.New("feed checkpoint moved: another import advanced it")

// FeedCheckpoint implements bundle.Checkpoint for one feed.
type FeedCheckpoint struct {
	db   *DB
	feed string
}

var _ bundle.Checkpoint = (*FeedCheckpoint)(nil)

// NewFeedCheckpoint returns the checkpoint of feed (one of the Feed*
// constants).
func NewFeedCheckpoint(db *DB, feed string) (*FeedCheckpoint, error) {
	switch feed {
	case FeedProgramFeed, FeedProgramFeedLocal, FeedVulnFeed:
	default:
		return nil, fmt.Errorf("unknown feed %q", feed)
	}
	return &FeedCheckpoint{db: db, feed: feed}, nil
}

// Feed is the row key.
func (c *FeedCheckpoint) Feed() string { return c.feed }

func loadCheckpoint(ctx context.Context, q queryRower, feed string, lock bool) (bundle.State, error) {
	st := bundle.State{Feed: feed}
	query := `SELECT applied_sequence, in_progress_sequence, kind, manifest_sha256, next_chunk, updated_at
		FROM feed_checkpoints WHERE feed = $1`
	if lock {
		query += ` FOR UPDATE`
	}
	var applied, inProgress int64
	var next int
	err := q.QueryRowContext(ctx, query, feed).Scan(&applied, &inProgress, &st.Kind, &st.Manifest, &next, &st.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return st, nil
	}
	if err != nil {
		return st, fmt.Errorf("read feed checkpoint: %w", err)
	}
	st.Applied, st.InProgress, st.NextChunk = uint64(max(applied, 0)), uint64(max(inProgress, 0)), next //nolint:gosec // non-negative (CHECK)
	return st, nil
}

// Load implements bundle.Checkpoint (the zero State before the first
// import).
func (c *FeedCheckpoint) Load(ctx context.Context) (bundle.State, error) {
	return loadCheckpoint(ctx, c.db, c.feed, false)
}

func checkpointArgs(s bundle.State) (applied, inProgress int64, next int, err error) {
	if s.Applied > math.MaxInt64 || s.InProgress > math.MaxInt64 || s.NextChunk < 0 || s.NextChunk > math.MaxInt32 {
		return 0, 0, 0, errors.New("feed checkpoint out of range")
	}
	return int64(s.Applied), int64(s.InProgress), s.NextChunk, nil //nolint:gosec // checked above
}

type execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// saveCheckpoint upserts the row. It never lowers the applied sequence: a
// stale run (or a replay of an older bundle) cannot roll the feed back.
func saveCheckpoint(ctx context.Context, e execer, feed string, s bundle.State) error {
	applied, inProgress, next, err := checkpointArgs(s)
	if err != nil {
		return err
	}
	at := s.UpdatedAt
	if at.IsZero() {
		at = time.Now()
	}
	res, err := e.ExecContext(ctx, `
		INSERT INTO feed_checkpoints (feed, applied_sequence, in_progress_sequence, kind, manifest_sha256, next_chunk, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (feed) DO UPDATE SET applied_sequence = EXCLUDED.applied_sequence,
		       in_progress_sequence = EXCLUDED.in_progress_sequence, kind = EXCLUDED.kind,
		       manifest_sha256 = EXCLUDED.manifest_sha256, next_chunk = EXCLUDED.next_chunk, updated_at = EXCLUDED.updated_at
		WHERE feed_checkpoints.applied_sequence <= EXCLUDED.applied_sequence`,
		feed, applied, inProgress, s.Kind, s.Manifest, next, at)
	if err != nil {
		return fmt.Errorf("save feed checkpoint: %w", err)
	}
	if n, err := res.RowsAffected(); err == nil && n == 0 {
		return fmt.Errorf("%w: applied sequence %d is older than the stored one", ErrCheckpointMoved, s.Applied)
	}
	return nil
}

// Save implements bundle.Checkpoint.
func (c *FeedCheckpoint) Save(ctx context.Context, s bundle.State) error {
	return saveCheckpoint(ctx, c.db, c.feed, s)
}

// AdvanceTx records, inside the caller's transaction, that the chunk
// before next.NextChunk was applied. It locks the row and refuses unless
// the stored checkpoint is exactly the bundle in progress at the previous
// chunk, so two runs (or a run racing a whole-bundle import) never both
// apply a chunk: the loser's transaction rolls back.
func (c *FeedCheckpoint) AdvanceTx(ctx context.Context, tx *sql.Tx, next bundle.State) error {
	cur, err := loadCheckpoint(ctx, tx, c.feed, true)
	if err != nil {
		return err
	}
	if cur.InProgress != next.InProgress || cur.Kind != next.Kind || cur.Manifest != next.Manifest ||
		cur.Applied != next.Applied || cur.NextChunk != next.NextChunk-1 {
		return fmt.Errorf("%w: stored %d/%s chunk %d, run %d/%s chunk %d", ErrCheckpointMoved,
			cur.InProgress, cur.Kind, cur.NextChunk, next.InProgress, next.Kind, next.NextChunk-1)
	}
	return saveCheckpoint(ctx, tx, c.feed, next)
}

// CompleteTx records, inside the caller's transaction, that sequence done
// was applied completely. It refuses a sequence not newer than the stored
// applied one.
func (c *FeedCheckpoint) CompleteTx(ctx context.Context, tx *sql.Tx, done bundle.State) error {
	cur, err := loadCheckpoint(ctx, tx, c.feed, true)
	if err != nil {
		return err
	}
	if cur.Applied >= done.Applied {
		return fmt.Errorf("%w: sequence %d is not newer than the applied %d", ErrCheckpointMoved, done.Applied, cur.Applied)
	}
	return saveCheckpoint(ctx, tx, c.feed, bundle.State{Applied: done.Applied, UpdatedAt: done.UpdatedAt})
}
