package postgres

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// execFindingStatusWrite runs a statement that may change findings.status.
// For a person's move (vulnerability.WithPersonMove) it runs in a transaction
// marked openctem.person_move, so the regression trigger (migration 002155)
// does not count a person moving a finding back from resolved (Undo, a
// correction) as a regression.
func (db *DB) execFindingStatusWrite(ctx context.Context, query string, args ...any) (sql.Result, error) {
	if !vulnerability.IsPersonMove(ctx) {
		return db.ExecContext(ctx, query, args...)
	}
	var res sql.Result
	err := db.Transaction(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `SELECT set_config('openctem.person_move', 'on', true)`); err != nil {
			return fmt.Errorf("mark person move: %w", err)
		}
		var err error
		res, err = tx.ExecContext(ctx, query, args...)
		return err
	})
	return res, err
}
