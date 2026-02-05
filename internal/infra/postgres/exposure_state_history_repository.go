package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/api/pkg/domain/exposure"
	"github.com/openctemio/api/pkg/domain/shared"
)

// ExposureStateHistoryRepository implements exposure.StateHistoryRepository using PostgreSQL.
type ExposureStateHistoryRepository struct {
	db *DB
}

// NewExposureStateHistoryRepository creates a new ExposureStateHistoryRepository.
func NewExposureStateHistoryRepository(db *DB) *ExposureStateHistoryRepository {
	return &ExposureStateHistoryRepository{db: db}
}

// Create persists a new state history entry.
func (r *ExposureStateHistoryRepository) Create(ctx context.Context, history *exposure.StateHistory) error {
	query := `
		INSERT INTO exposure_state_history (
			id, exposure_event_id, previous_state, new_state, changed_by, reason, created_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`

	_, err := r.db.ExecContext(ctx, query,
		history.ID().String(),
		history.ExposureEventID().String(),
		history.PreviousState().String(),
		history.NewState().String(),
		nullIDPtr(history.ChangedBy()),
		nullString(history.Reason()),
		history.CreatedAt(),
	)

	if err != nil {
		return fmt.Errorf("failed to create exposure state history: %w", err)
	}

	return nil
}

// ListByExposureEvent retrieves all state history for an exposure event.
func (r *ExposureStateHistoryRepository) ListByExposureEvent(ctx context.Context, exposureEventID shared.ID) ([]*exposure.StateHistory, error) {
	query := r.selectQuery() + " WHERE exposure_event_id = $1 ORDER BY created_at DESC"

	rows, err := r.db.QueryContext(ctx, query, exposureEventID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to query state history: %w", err)
	}
	defer rows.Close()

	var histories []*exposure.StateHistory
	for rows.Next() {
		history, err := r.scanHistoryFromRows(rows)
		if err != nil {
			return nil, err
		}
		histories = append(histories, history)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate state history: %w", err)
	}

	return histories, nil
}

// GetLatest retrieves the most recent state change for an exposure event.
func (r *ExposureStateHistoryRepository) GetLatest(ctx context.Context, exposureEventID shared.ID) (*exposure.StateHistory, error) {
	query := r.selectQuery() + " WHERE exposure_event_id = $1 ORDER BY created_at DESC LIMIT 1"

	row := r.db.QueryRowContext(ctx, query, exposureEventID.String())
	return r.scanHistory(row)
}

// Helper methods

func (r *ExposureStateHistoryRepository) selectQuery() string {
	return `
		SELECT id, exposure_event_id, previous_state, new_state, changed_by, reason, created_at
		FROM exposure_state_history
	`
}

func (r *ExposureStateHistoryRepository) scanHistory(row *sql.Row) (*exposure.StateHistory, error) {
	history, err := r.doScan(row.Scan)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, exposure.ErrStateHistoryNotFound
		}
		return nil, fmt.Errorf("failed to scan state history: %w", err)
	}
	return history, nil
}

func (r *ExposureStateHistoryRepository) scanHistoryFromRows(rows *sql.Rows) (*exposure.StateHistory, error) {
	return r.doScan(rows.Scan)
}

func (r *ExposureStateHistoryRepository) doScan(scan func(dest ...any) error) (*exposure.StateHistory, error) {
	var (
		idStr              string
		exposureEventIDStr string
		previousState      string
		newState           string
		changedByStr       sql.NullString
		reason             sql.NullString
		createdAt          time.Time
	)

	err := scan(
		&idStr, &exposureEventIDStr, &previousState, &newState, &changedByStr, &reason, &createdAt,
	)
	if err != nil {
		return nil, err
	}

	parsedID, err := shared.IDFromString(idStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse id: %w", err)
	}

	exposureEventID, err := shared.IDFromString(exposureEventIDStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse exposure event id: %w", err)
	}

	parsedPreviousState, _ := exposure.ParseState(previousState)
	parsedNewState, _ := exposure.ParseState(newState)
	changedBy := parseNullID(changedByStr)

	return exposure.ReconstituteStateHistory(
		parsedID,
		exposureEventID,
		parsedPreviousState,
		parsedNewState,
		changedBy,
		nullStringValue(reason),
		createdAt,
	), nil
}
