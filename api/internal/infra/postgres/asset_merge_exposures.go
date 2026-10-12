package postgres

// Exposure events in an asset merge (RFC-043 P0, B20).
//
// An exposure event's fingerprint embeds its asset id
// (exposure.Fingerprint), so an event moved to the kept asset must be
// re-keyed, or the next scan of the kept asset would create a second event and
// the moved one would never auto-resolve. When the re-keyed fingerprint is
// already taken, the two events are one exposure: the earliest-created one
// survives, takes the stronger state and the wider seen-window, inherits the
// other's state history, and the other is removed. Nothing is lost: an
// exposure event has no other state, and its history moves to the survivor.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/exposure"
)

type mergeExposure struct {
	id, assetID, fingerprint            string
	eventType, title, source, detailsJS string
	createdAt                           time.Time
}

// rekeyMergedExposures re-keys the exposure events of the merged assets for
// the kept asset, folding each collision into one survivor. It runs inside the
// merge transaction, before the events are moved.
func rekeyMergedExposures(ctx context.Context, tx *sql.Tx, tenantID, keepID string, mergeIDs []string) error {
	moved, err := listMergedExposures(ctx, tx, tenantID, mergeIDs)
	if err != nil {
		return err
	}
	for _, e := range moved {
		if err := rekeyMergedExposure(ctx, tx, tenantID, keepID, e); err != nil {
			return err
		}
	}
	return nil
}

func listMergedExposures(ctx context.Context, tx *sql.Tx, tenantID string, mergeIDs []string) ([]mergeExposure, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT id, asset_id, fingerprint, event_type, title, source, details::text, created_at
		FROM exposure_events
		WHERE tenant_id = $1 AND asset_id = ANY($2)
		ORDER BY created_at, id
		FOR UPDATE`, tenantID, pq.Array(mergeIDs))
	if err != nil {
		return nil, fmt.Errorf("list merged exposure events: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []mergeExposure
	for rows.Next() {
		var e mergeExposure
		if err := rows.Scan(&e.id, &e.assetID, &e.fingerprint, &e.eventType, &e.title, &e.source,
			&e.detailsJS, &e.createdAt); err != nil {
			return nil, fmt.Errorf("scan merged exposure event: %w", err)
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list merged exposure events: %w", err)
	}
	return out, nil
}

func rekeyMergedExposure(ctx context.Context, tx *sql.Tx, tenantID, keepID string, e mergeExposure) error {
	var details map[string]any
	if err := json.Unmarshal([]byte(e.detailsJS), &details); err != nil {
		return nil //nolint:nilerr // unreadable details: leave the event as it is
	}
	// Only re-key an event whose stored columns still reproduce its stored
	// fingerprint; anything else was keyed by a rule we cannot reproduce.
	if exposure.Fingerprint(tenantID, e.eventType, e.title, e.source, e.assetID, details) != e.fingerprint {
		return nil
	}
	newFP := exposure.Fingerprint(tenantID, e.eventType, e.title, e.source, keepID, details)

	var holderID string
	var holderCreated time.Time
	err := tx.QueryRowContext(ctx,
		`SELECT id, created_at FROM exposure_events WHERE tenant_id = $1 AND fingerprint = $2 FOR UPDATE`,
		tenantID, newFP).Scan(&holderID, &holderCreated)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		if _, err := tx.ExecContext(ctx,
			`UPDATE exposure_events SET fingerprint = $1 WHERE id = $2 AND tenant_id = $3`,
			newFP, e.id, tenantID); err != nil {
			return fmt.Errorf("re-key merged exposure event: %w", err)
		}
		return nil
	case err != nil:
		return fmt.Errorf("look up re-keyed exposure fingerprint: %w", err)
	case !e.createdAt.Before(holderCreated):
		return mergeExposureInto(ctx, tx, tenantID, holderID, e.id, "")
	default:
		return mergeExposureInto(ctx, tx, tenantID, e.id, holderID, newFP)
	}
}

// exposureStateRank: a deliberate decision beats an open event, which beats
// an auto-resolved one, so folding never reopens an accepted risk or closes
// an exposure that is still active.
const exposureStateRankSQL = `CASE %s WHEN 'accepted' THEN 3 WHEN 'false_positive' THEN 3 WHEN 'active' THEN 2 ELSE 1 END`

// mergeExposureInto folds loser into survivor and removes the loser. When
// newFP is set the survivor takes that fingerprint after the loser is gone.
func mergeExposureInto(ctx context.Context, tx *sql.Tx, tenantID, survivorID, loserID, newFP string) error {
	rankS := fmt.Sprintf(exposureStateRankSQL, "s.state")
	rankL := fmt.Sprintf(exposureStateRankSQL, "l.state")
	//nolint:gosec // G201: only the fixed rank expression is formatted in.
	q := fmt.Sprintf(`
		UPDATE exposure_events s SET
			first_seen_at = LEAST(s.first_seen_at, l.first_seen_at),
			last_seen_at = GREATEST(s.last_seen_at, l.last_seen_at),
			state = CASE WHEN %[2]s > %[1]s THEN l.state ELSE s.state END,
			resolved_at = CASE WHEN %[2]s > %[1]s THEN l.resolved_at ELSE s.resolved_at END,
			resolved_by = CASE WHEN %[2]s > %[1]s THEN l.resolved_by ELSE s.resolved_by END,
			resolution_notes = CASE WHEN %[2]s > %[1]s THEN l.resolution_notes ELSE s.resolution_notes END
		FROM exposure_events l
		WHERE s.id = $1 AND s.tenant_id = $3 AND l.id = $2 AND l.tenant_id = $3`, rankS, rankL)
	if _, err := tx.ExecContext(ctx, q, survivorID, loserID, tenantID); err != nil {
		return fmt.Errorf("fold exposure event state: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE exposure_state_history SET exposure_event_id = $1 WHERE exposure_event_id = $2`,
		survivorID, loserID); err != nil {
		return fmt.Errorf("move exposure state history: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO exposure_state_history (exposure_event_id, previous_state, new_state, reason)
		SELECT id, state, state, $2 FROM exposure_events WHERE id = $1`,
		survivorID, "asset merge: folded duplicate exposure event "+loserID); err != nil {
		return fmt.Errorf("record exposure merge: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM exposure_events WHERE id = $1 AND tenant_id = $2`, loserID, tenantID); err != nil {
		return fmt.Errorf("remove folded exposure event: %w", err)
	}
	if newFP != "" {
		if _, err := tx.ExecContext(ctx,
			`UPDATE exposure_events SET fingerprint = $1 WHERE id = $2 AND tenant_id = $3`,
			newFP, survivorID, tenantID); err != nil {
			return fmt.Errorf("re-key surviving exposure event: %w", err)
		}
	}
	return nil
}
