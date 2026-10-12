package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// CommentReactionRepository persists emoji reactions on finding comments.
type CommentReactionRepository struct {
	db *DB
}

// NewCommentReactionRepository creates a CommentReactionRepository.
func NewCommentReactionRepository(db *DB) *CommentReactionRepository {
	return &CommentReactionRepository{db: db}
}

var _ vulnerability.CommentReactionRepository = (*CommentReactionRepository)(nil)

// Add records the reaction. It locks the comment row first, so the two caps
// (distinct emoji per comment, reactions per user per comment) are checked
// and the row inserted without a concurrent request slipping in between.
func (r *CommentReactionRepository) Add(ctx context.Context, tenantID, commentID, userID shared.ID, emoji string) (bool, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("begin reaction tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var locked string
	err = tx.QueryRowContext(ctx,
		`SELECT id FROM finding_comments WHERE id = $1 AND tenant_id = $2 FOR UPDATE`,
		commentID.String(), tenantID.String()).Scan(&locked)
	if errors.Is(err, sql.ErrNoRows) {
		return false, fmt.Errorf("%w: comment not found", shared.ErrNotFound)
	}
	if err != nil {
		return false, fmt.Errorf("lock comment: %w", err)
	}

	var exists, emojiUsed bool
	var distinct, mine int
	err = tx.QueryRowContext(ctx, `
		SELECT
			COALESCE(BOOL_OR(user_id = $3 AND emoji = $4), false),
			COALESCE(BOOL_OR(emoji = $4), false),
			COUNT(DISTINCT emoji),
			COUNT(*) FILTER (WHERE user_id = $3)
		FROM comment_reactions
		WHERE tenant_id = $1 AND comment_id = $2`,
		tenantID.String(), commentID.String(), userID.String(), emoji,
	).Scan(&exists, &emojiUsed, &distinct, &mine)
	if err != nil {
		return false, fmt.Errorf("count reactions: %w", err)
	}
	if exists {
		return false, nil
	}
	if err := vulnerability.CheckReactionCaps(emojiUsed, distinct, mine); err != nil {
		return false, err
	}

	res, err := tx.ExecContext(ctx, `
		INSERT INTO comment_reactions (tenant_id, comment_id, user_id, emoji)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (comment_id, user_id, emoji) DO NOTHING`,
		tenantID.String(), commentID.String(), userID.String(), emoji)
	if err != nil {
		return false, fmt.Errorf("insert reaction: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("insert reaction: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("commit reaction: %w", err)
	}
	return n > 0, nil
}

// Remove deletes the reaction and reports whether it existed.
func (r *CommentReactionRepository) Remove(ctx context.Context, tenantID, commentID, userID shared.ID, emoji string) (bool, error) {
	res, err := r.db.ExecContext(ctx, `
		DELETE FROM comment_reactions
		WHERE tenant_id = $1 AND comment_id = $2 AND user_id = $3 AND emoji = $4`,
		tenantID.String(), commentID.String(), userID.String(), emoji)
	if err != nil {
		return false, fmt.Errorf("delete reaction: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("delete reaction: %w", err)
	}
	return n > 0, nil
}

// Summaries aggregates reactions for all commentIDs in one query. Emoji are
// ordered by first use (MIN(created_at)) so a comment's pills keep their
// place as counts change; sample users are the earliest reactors.
func (r *CommentReactionRepository) Summaries(
	ctx context.Context, tenantID shared.ID, commentIDs []shared.ID, viewerID shared.ID,
) (map[shared.ID][]vulnerability.ReactionSummary, error) {
	out := make(map[shared.ID][]vulnerability.ReactionSummary, len(commentIDs))
	if len(commentIDs) == 0 {
		return out, nil
	}
	ids := make([]string, len(commentIDs))
	for i, id := range commentIDs {
		ids[i] = id.String()
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT cr.comment_id,
		       cr.emoji,
		       COUNT(*) AS reaction_count,
		       COALESCE(BOOL_OR(cr.user_id = $3), false) AS reacted_by_me,
		       (ARRAY_AGG(cr.user_id::text ORDER BY cr.created_at, cr.id))[1:$4] AS sample_ids,
		       (ARRAY_AGG(COALESCE(NULLIF(u.name, ''), u.email, '') ORDER BY cr.created_at, cr.id))[1:$4] AS sample_names
		FROM comment_reactions cr
		LEFT JOIN users u ON u.id = cr.user_id
		WHERE cr.tenant_id = $1 AND cr.comment_id = ANY($2::uuid[])
		GROUP BY cr.comment_id, cr.emoji
		ORDER BY cr.comment_id, MIN(cr.created_at), cr.emoji`,
		tenantID.String(), pq.Array(ids), viewerID.String(), vulnerability.ReactionSampleUsers)
	if err != nil {
		return nil, fmt.Errorf("query reaction summaries: %w", err)
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var (
			commentIDStr string
			s            vulnerability.ReactionSummary
			sampleIDs    pq.StringArray
			sampleNames  pq.StringArray
		)
		if err := rows.Scan(&commentIDStr, &s.Emoji, &s.Count, &s.ReactedByMe, &sampleIDs, &sampleNames); err != nil {
			return nil, fmt.Errorf("scan reaction summary: %w", err)
		}
		commentID, err := shared.IDFromString(commentIDStr)
		if err != nil {
			return nil, fmt.Errorf("parse comment id: %w", err)
		}
		s.SampleUsers = make([]vulnerability.ReactionUser, 0, len(sampleIDs))
		for i, idStr := range sampleIDs {
			uid, err := shared.IDFromString(idStr)
			if err != nil {
				continue
			}
			name := ""
			if i < len(sampleNames) {
				name = sampleNames[i]
			}
			s.SampleUsers = append(s.SampleUsers, vulnerability.ReactionUser{ID: uid, Name: name})
		}
		out[commentID] = append(out[commentID], s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate reaction summaries: %w", err)
	}
	return out, nil
}
