package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// findingTransition says who moved findings and why (see
// vulnerability.StatusTransition). A platform writer sets it on its
// transaction (setFindingTransition) before it changes findings.status; the
// trigger trg_findings_record_transition (migration 002180) then writes one
// timeline entry per finding it moved, in the same transaction, with the old
// and the new status. A move the platform makes is therefore never missing
// from a finding's timeline, and the entry never exists without the move.
type findingTransition = vulnerability.StatusTransition

// setFindingTransition names the writer of every status change the rest of
// tx makes (transaction-local). Evidence attached to ctx
// (vulnerability.WithTransitionEvidence) is merged into its changes.
func setFindingTransition(ctx context.Context, tx *sql.Tx, t findingTransition) error {
	if ev := vulnerability.TransitionEvidence(ctx); len(ev) > 0 {
		merged := make(map[string]any, len(ev)+len(t.Changes))
		for k, v := range ev {
			merged[k] = v
		}
		for k, v := range t.Changes {
			merged[k] = v
		}
		t.Changes = merged
	}
	raw, err := json.Marshal(t)
	if err != nil {
		return fmt.Errorf("marshal finding transition: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `SELECT set_config('openctem.transition', $1, true)`, string(raw)); err != nil {
		return fmt.Errorf("set finding transition: %w", err)
	}
	return nil
}

// withFindingTransition runs fn in a transaction whose status changes are
// recorded as t (see findingTransition).
func (db *DB) withFindingTransition(ctx context.Context, t findingTransition, fn func(tx *sql.Tx) error) error {
	return db.Transaction(ctx, func(tx *sql.Tx) error {
		if err := setFindingTransition(ctx, tx, t); err != nil {
			return err
		}
		return fn(tx)
	})
}

// queryIDsWithTransition runs one status-writing statement whose first
// returned column is a finding id, recorded as t, and returns the ids.
func (db *DB) queryIDsWithTransition(ctx context.Context, t findingTransition, query string, args ...any) ([]shared.ID, error) {
	var out []shared.ID
	err := db.withFindingTransition(ctx, t, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, query, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var s string
			if err := rows.Scan(&s); err != nil {
				return err
			}
			if id, err := shared.IDFromString(s); err == nil {
				out = append(out, id)
			}
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// execWithTransition runs one status-writing statement recorded as t and
// returns the rows it affected.
func (db *DB) execWithTransition(ctx context.Context, t findingTransition, query string, args ...any) (int64, error) {
	var n int64
	err := db.withFindingTransition(ctx, t, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, query, args...)
		if err != nil {
			return err
		}
		n, _ = res.RowsAffected()
		return nil
	})
	return n, err
}

// clearFindingTransition stops recording status changes as the transition
// set earlier in tx (a writer that records its own entries for later moves).
func clearFindingTransition(ctx context.Context, tx *sql.Tx) error {
	if _, err := tx.ExecContext(ctx, `SELECT set_config('openctem.transition', '', true)`); err != nil {
		return fmt.Errorf("clear finding transition: %w", err)
	}
	return nil
}

// execStatusWrite runs a statement that may change findings.status. When ctx
// carries a vulnerability.StatusTransition (an application path moving a
// finding on the platform's behalf), it runs in a transaction recorded as
// that transition, so the move and its timeline entry commit together. When
// ctx marks a person's move (vulnerability.WithPersonMove), the transaction is
// marked openctem.person_move, so the regression trigger does not count a
// person moving a finding back from resolved (Undo, a correction). Otherwise it
// runs as is.
func (db *DB) execStatusWrite(ctx context.Context, query string, args ...any) (sql.Result, error) {
	t, platform := vulnerability.StatusTransitionFrom(ctx)
	person := vulnerability.IsPersonMove(ctx)
	if !platform && !person {
		return db.ExecContext(ctx, query, args...)
	}
	var res sql.Result
	err := db.Transaction(ctx, func(tx *sql.Tx) error {
		if platform {
			if err := setFindingTransition(ctx, tx, t); err != nil {
				return err
			}
		}
		if person {
			if _, err := tx.ExecContext(ctx, `SELECT set_config('openctem.person_move', 'on', true)`); err != nil {
				return fmt.Errorf("mark person move: %w", err)
			}
		}
		var err error
		res, err = tx.ExecContext(ctx, query, args...)
		return err
	})
	return res, err
}
