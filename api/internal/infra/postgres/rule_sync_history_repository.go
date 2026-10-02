package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/openctemio/api/pkg/domain/rule"
	"github.com/openctemio/api/pkg/domain/shared"
)

// RuleSyncHistoryRepository implements rule.SyncHistoryRepository using PostgreSQL.
type RuleSyncHistoryRepository struct {
	db *DB
}

// NewRuleSyncHistoryRepository creates a new RuleSyncHistoryRepository.
func NewRuleSyncHistoryRepository(db *DB) *RuleSyncHistoryRepository {
	return &RuleSyncHistoryRepository{db: db}
}

// Create persists a new sync history record.
func (r *RuleSyncHistoryRepository) Create(ctx context.Context, history *rule.SyncHistory) error {
	query := `
		INSERT INTO rule_sync_history (
			id, source_id, status, rules_added, rules_updated, rules_removed,
			duration_ms, error_message, error_details, previous_hash, new_hash,
			created_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
	`

	errorDetails, _ := toJSONB(history.ErrorDetails)

	_, err := r.db.ExecContext(ctx, query,
		history.ID.String(),
		history.SourceID.String(),
		string(history.Status),
		history.RulesAdded,
		history.RulesUpdated,
		history.RulesRemoved,
		history.Duration.Milliseconds(),
		nullString(history.ErrorMessage),
		errorDetails,
		nullString(history.PreviousHash),
		nullString(history.NewHash),
		history.CreatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to create sync history: %w", err)
	}

	return nil
}

// ListBySource lists sync history for a source.
func (r *RuleSyncHistoryRepository) ListBySource(ctx context.Context, sourceID shared.ID, limit int) ([]*rule.SyncHistory, error) {
	query := `
		SELECT id, source_id, status, rules_added, rules_updated, rules_removed,
		       duration_ms, error_message, error_details, previous_hash, new_hash,
		       created_at
		FROM rule_sync_history
		WHERE source_id = $1
		ORDER BY created_at DESC
		LIMIT $2
	`

	rows, err := r.db.QueryContext(ctx, query, sourceID.String(), limit)
	if err != nil {
		return nil, fmt.Errorf("failed to list sync history: %w", err)
	}
	defer rows.Close()

	var histories []*rule.SyncHistory
	for rows.Next() {
		history, err := r.scanHistory(rows)
		if err != nil {
			return nil, err
		}
		histories = append(histories, history)
	}

	return histories, nil
}

func (r *RuleSyncHistoryRepository) scanHistory(rows *sql.Rows) (*rule.SyncHistory, error) {
	var (
		h            rule.SyncHistory
		id           string
		sourceID     string
		status       string
		durationMs   int64
		errorMessage sql.NullString
		errorDetails []byte
		previousHash sql.NullString
		newHash      sql.NullString
	)

	err := rows.Scan(
		&id, &sourceID, &status, &h.RulesAdded, &h.RulesUpdated, &h.RulesRemoved,
		&durationMs, &errorMessage, &errorDetails, &previousHash, &newHash,
		&h.CreatedAt,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to scan sync history: %w", err)
	}

	h.ID, _ = shared.IDFromString(id)
	h.SourceID, _ = shared.IDFromString(sourceID)
	h.Status = rule.SyncStatus(status)
	h.Duration = time.Duration(durationMs) * time.Millisecond

	if errorMessage.Valid {
		h.ErrorMessage = errorMessage.String
	}

	if len(errorDetails) > 0 {
		if err := fromJSONB(errorDetails, &h.ErrorDetails); err != nil {
			return nil, fmt.Errorf("failed to unmarshal error details: %w", err)
		}
	}

	if previousHash.Valid {
		h.PreviousHash = previousHash.String
	}

	if newHash.Valid {
		h.NewHash = newHash.String
	}

	return &h, nil
}

// Ensure interface compliance
var _ rule.SyncHistoryRepository = (*RuleSyncHistoryRepository)(nil)
