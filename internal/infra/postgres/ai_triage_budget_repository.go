package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/api/internal/app/aitriage"
	"github.com/openctemio/api/pkg/domain/shared"
)

// AITriageBudgetRepository implements aitriage.BudgetRepository
// against PostgreSQL. Backed by the ai_triage_budgets table
// (migration 000163 — see RFC-008 §3.1 for schema rationale).
//
// Invariant: exactly one row per (tenant_id, period_start) — enforced
// by the UNIQUE constraint. GetOrCreate uses INSERT … ON CONFLICT
// DO UPDATE so concurrent requests at month-rollover converge to a
// single row rather than racing and producing duplicates.
//
// IncrementUsed is the hot path: called after every successful LLM
// triage call. It must be atomic across concurrent pods (multi-pod
// deployments race; the counter is the only credibility the budget
// has). We use `UPDATE … RETURNING` so the returned tokens_used is
// the post-increment value observed by the transaction.
type AITriageBudgetRepository struct {
	db *DB
}

// NewAITriageBudgetRepository wires the repo.
func NewAITriageBudgetRepository(db *DB) *AITriageBudgetRepository {
	return &AITriageBudgetRepository{db: db}
}

// GetOrCreate returns the budget row for (tenantID, periodStart) or
// creates it with defaultLimit on first call in the period. Uses
// INSERT … ON CONFLICT DO NOTHING then SELECT to avoid a race where
// two pods both SELECT-miss and both INSERT.
//
// defaultLimit = 0 means "unlimited" per the schema convention.
// Thresholds left NULL so the service layer applies its defaults
// (80% warn / 100% block).
func (r *AITriageBudgetRepository) GetOrCreate(
	ctx context.Context,
	tenantID shared.ID,
	periodStart time.Time,
	periodEnd time.Time,
	defaultLimit int64,
) (*aitriage.BudgetRow, error) {
	// 1. Try to insert a fresh row. ON CONFLICT on the unique
	//    constraint makes this idempotent — either we win the race
	//    and own the new row, or another pod did and we fall through
	//    to the SELECT below with the existing row.
	const insertQ = `
		INSERT INTO ai_triage_budgets (
			tenant_id, period_start, period_end, token_limit
		) VALUES ($1, $2, $3, $4)
		ON CONFLICT (tenant_id, period_start) DO NOTHING
	`
	if _, err := r.db.ExecContext(ctx, insertQ,
		tenantID.String(), periodStart.UTC(), periodEnd.UTC(), defaultLimit,
	); err != nil {
		return nil, fmt.Errorf("budget upsert: %w", err)
	}

	// 2. Read back the row. Whether we just inserted or collided with
	//    an existing one, the unique key identifies exactly one.
	return r.selectOne(ctx, tenantID, periodStart)
}

// IncrementUsed atomically adds delta to tokens_used and returns the
// post-increment value. Returns an error if the row doesn't exist
// (caller should have called GetOrCreate first — but we don't silently
// create here because an Increment without a prior GetOrCreate signals
// a logic bug, not a missing row).
func (r *AITriageBudgetRepository) IncrementUsed(
	ctx context.Context,
	tenantID shared.ID,
	periodStart time.Time,
	delta int64,
) (int64, error) {
	if delta < 0 {
		// Defensive: never decrement the counter. A negative delta
		// would erase legitimate spend from the tenant's invoice
		// history and silently allow overspending. Reject at the
		// repo boundary so a bug elsewhere can't cause this.
		return 0, fmt.Errorf("negative delta rejected: %d", delta)
	}

	const q = `
		UPDATE ai_triage_budgets
		SET tokens_used = tokens_used + $3,
		    updated_at  = NOW()
		WHERE tenant_id = $1
		  AND period_start = $2
		RETURNING tokens_used
	`
	var newUsed int64
	err := r.db.QueryRowContext(ctx, q,
		tenantID.String(), periodStart.UTC(), delta,
	).Scan(&newUsed)

	if errors.Is(err, sql.ErrNoRows) {
		return 0, fmt.Errorf("budget row not found for tenant=%s period=%s — call GetOrCreate first",
			tenantID, periodStart.Format("2006-01-02"))
	}
	if err != nil {
		return 0, fmt.Errorf("budget increment: %w", err)
	}
	return newUsed, nil
}

// UpdateLastWarnSent records the tokens_used value at which a warn
// notification was last emitted. Used to prevent re-emission: the
// service layer only fires a new warn when tokens_used has re-crossed
// the threshold AFTER last_warn_sent_used.
//
// Statically-embedded UPDATE (no runtime column interpolation) so
// CodeQL / staticcheck can flow-analyse the SQL end-to-end without
// chasing a map lookup. The duplication with UpdateLastBlockSent is
// two lines — worth it to avoid a Sprintf-built query.
func (r *AITriageBudgetRepository) UpdateLastWarnSent(
	ctx context.Context,
	tenantID shared.ID,
	periodStart time.Time,
	used int64,
) error {
	const q = `
		UPDATE ai_triage_budgets
		SET last_warn_sent_used = $3,
		    updated_at          = NOW()
		WHERE tenant_id    = $1
		  AND period_start = $2
	`
	if _, err := r.db.ExecContext(ctx, q,
		tenantID.String(), periodStart.UTC(), used,
	); err != nil {
		return fmt.Errorf("budget update last_warn_sent_used: %w", err)
	}
	return nil
}

// UpdateLastBlockSent mirrors UpdateLastWarnSent for the block event.
// See that function's comment for why each path carries its own
// literal SQL.
func (r *AITriageBudgetRepository) UpdateLastBlockSent(
	ctx context.Context,
	tenantID shared.ID,
	periodStart time.Time,
	used int64,
) error {
	const q = `
		UPDATE ai_triage_budgets
		SET last_block_sent_used = $3,
		    updated_at           = NOW()
		WHERE tenant_id    = $1
		  AND period_start = $2
	`
	if _, err := r.db.ExecContext(ctx, q,
		tenantID.String(), periodStart.UTC(), used,
	); err != nil {
		return fmt.Errorf("budget update last_block_sent_used: %w", err)
	}
	return nil
}

// selectOne is the shared SELECT helper used by GetOrCreate. Hidden
// because it's only correct when the unique constraint guarantees
// zero-or-one rows.
func (r *AITriageBudgetRepository) selectOne(
	ctx context.Context,
	tenantID shared.ID,
	periodStart time.Time,
) (*aitriage.BudgetRow, error) {
	const q = `
		SELECT
			tenant_id, period_start, period_end,
			token_limit, tokens_used,
			COALESCE(warn_threshold_pct, 0),
			COALESCE(block_threshold_pct, 0),
			last_warn_sent_used, last_block_sent_used
		FROM ai_triage_budgets
		WHERE tenant_id = $1 AND period_start = $2
	`
	row := &aitriage.BudgetRow{}
	var tenantStr string
	err := r.db.QueryRowContext(ctx, q,
		tenantID.String(), periodStart.UTC(),
	).Scan(
		&tenantStr,
		&row.PeriodStart,
		&row.PeriodEnd,
		&row.TokenLimit,
		&row.TokensUsed,
		&row.WarnThresholdPct,
		&row.BlockThresholdPct,
		&row.LastWarnSentUsed,
		&row.LastBlockSentUsed,
	)
	if errors.Is(err, sql.ErrNoRows) {
		// Should be impossible when called from GetOrCreate, but
		// surface clearly instead of returning a zero-row.
		return nil, fmt.Errorf("budget row vanished mid-upsert for tenant=%s", tenantID)
	}
	if err != nil {
		return nil, fmt.Errorf("budget select: %w", err)
	}
	parsed, idErr := shared.IDFromString(tenantStr)
	if idErr != nil {
		return nil, fmt.Errorf("budget tenant id parse: %w", idErr)
	}
	row.TenantID = parsed
	return row, nil
}

