package aitriage

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

// Budget errors — exported so callers can branch on them.
var (
	// ErrBudgetExceeded is returned by BudgetService.Check when the
	// tenant has used tokens up to or past block_threshold_pct of
	// its monthly limit. Callers MUST fail the triage call without
	// invoking the LLM.
	ErrBudgetExceeded = errors.New("ai-triage monthly token budget exceeded")

	// ErrBudgetUnavailable is returned when the budget repository
	// cannot answer (DB down, Redis down). The service's strict-mode
	// flag controls whether callers treat this as fail-closed.
	ErrBudgetUnavailable = errors.New("ai-triage budget service unavailable")
)

// BudgetStatus is the read-model for dashboards and admin endpoints.
// Zero-valued Limit means "unlimited" per the schema convention.
type BudgetStatus struct {
	TenantID    shared.ID
	PeriodStart time.Time
	PeriodEnd   time.Time
	Limit       int64
	Used        int64
	Remaining   int64 // 0 when Limit == 0 (unlimited)
	UsedPct     int   // 0 when Limit == 0

	// NeedsWarn is true when the current run (or the pre-check) has
	// crossed warn_threshold_pct and no warn event has been emitted
	// yet for the period. The service queries this when deciding
	// whether to enqueue a notification.
	NeedsWarn bool
}

// BudgetRepository persists and increments the monthly token counter.
// Implementation lives in internal/infra/postgres/ai_triage_budget_repository.go
// (not shipped in this PR; RFC-008 Phase 1 scaffolds the domain only).
//
// Contract:
//   - GetOrCreate is idempotent per (tenantID, periodStart). First
//     call in a month creates the row; later calls return it.
//   - IncrementUsed MUST be atomic (UPDATE … SET tokens_used =
//     tokens_used + $delta WHERE tenant_id = $1 AND period_start = $2
//     RETURNING tokens_used). Concurrent triage runs in multi-pod
//     deploys would otherwise race.
//   - UpdateLastWarnSent + UpdateLastBlockSent record which absolute
//     tokens_used value last fired a notification, so the service
//     doesn't spam after the first crossing.
type BudgetRepository interface {
	GetOrCreate(ctx context.Context, tenantID shared.ID, periodStart time.Time, periodEnd time.Time, defaultLimit int64) (*BudgetRow, error)
	IncrementUsed(ctx context.Context, tenantID shared.ID, periodStart time.Time, delta int64) (int64, error)
	UpdateLastWarnSent(ctx context.Context, tenantID shared.ID, periodStart time.Time, used int64) error
	UpdateLastBlockSent(ctx context.Context, tenantID shared.ID, periodStart time.Time, used int64) error
}

// BudgetRow mirrors the ai_triage_budgets schema for in-memory use.
type BudgetRow struct {
	TenantID          shared.ID
	PeriodStart       time.Time
	PeriodEnd         time.Time
	TokenLimit        int64 // 0 == unlimited
	TokensUsed        int64
	WarnThresholdPct  int // service default when stored as 0
	BlockThresholdPct int // service default when stored as 0
	LastWarnSentUsed  int64
	LastBlockSentUsed int64
}

// BudgetServiceConfig controls the service-layer defaults and the
// flag that governs whether Check enforces at all.
type BudgetServiceConfig struct {
	// Enabled gates the whole service. When false, Check always
	// returns nil and Record becomes a no-op. Phase 1 default.
	Enabled bool
	// Strict controls repo-failure behaviour. See ErrBudgetUnavailable.
	Strict bool
	// DefaultTokensPerMonth applied when a tenant's row has
	// token_limit = 0 AND the tenant has no plan override. 0 =
	// unlimited; see RFC-008 §3.5.
	DefaultTokensPerMonth int64
	// Threshold defaults when a row stores 0.
	DefaultWarnPct  int
	DefaultBlockPct int
}

// BudgetService is the enforcement + visibility surface called from
// triage service.go. It is safe to construct with a nil repo when
// Enabled = false — every method short-circuits. This is what lets
// RFC-008 Phase 1 ship with zero behaviour change.
type BudgetService struct {
	repo BudgetRepository
	cfg  BudgetServiceConfig
	log  *logger.Logger
}

// NewBudgetService returns a fully configured service. Zero-value
// warn/block percentages are filled to 80 / 100.
func NewBudgetService(repo BudgetRepository, cfg BudgetServiceConfig, log *logger.Logger) *BudgetService {
	if cfg.DefaultWarnPct == 0 {
		cfg.DefaultWarnPct = 80
	}
	if cfg.DefaultBlockPct == 0 {
		cfg.DefaultBlockPct = 100
	}
	if log == nil {
		log = logger.NewNop()
	}
	return &BudgetService{repo: repo, cfg: cfg, log: log.With("service", "ai-triage-budget")}
}

// Check is invoked BEFORE the LLM call. estimatedTokens is the
// caller's best-effort guess for (prompt + expected completion) so
// that Check can reject a call whose estimate would push the tenant
// past block_threshold_pct. The check uses the CURRENT tokens_used;
// actual usage is recorded post-call via Record.
//
// Phase 1: returns nil unconditionally when cfg.Enabled == false.
func (s *BudgetService) Check(ctx context.Context, tenantID shared.ID, estimatedTokens int) error {
	if !s.cfg.Enabled {
		return nil
	}
	if s.repo == nil {
		return s.repoUnavailable("repo=nil")
	}
	row, err := s.fetchOrInitRow(ctx, tenantID)
	if err != nil {
		return err
	}
	if row == nil {
		// Non-strict fallback path: repoUnavailable returned nil so
		// the caller can proceed. Treat as "unlimited" for this call.
		return nil
	}
	if row.TokenLimit == 0 { // unlimited
		return nil
	}
	blockPct := row.BlockThresholdPct
	if blockPct == 0 {
		blockPct = s.cfg.DefaultBlockPct
	}
	blockAt := row.TokenLimit * int64(blockPct) / 100
	if row.TokensUsed+int64(estimatedTokens) >= blockAt {
		return fmt.Errorf("%w: tenant=%s used=%d estimated=%d block_at=%d",
			ErrBudgetExceeded, tenantID, row.TokensUsed, estimatedTokens, blockAt)
	}
	return nil
}

// Record is invoked AFTER the LLM call with the actual token count
// from the provider response (prompt + completion). It atomically
// increments tokens_used and detects threshold crossings.
//
// Phase 1: no-op when cfg.Enabled == false. When enabled but repo
// fails, we log loud and return the error — caller decides to swallow
// or surface. Default handling in service.go is to log and continue
// (the LLM already ran, so we've already spent the tokens; refusing
// to record would just make the next tenant less accurately billed).
func (s *BudgetService) Record(ctx context.Context, tenantID shared.ID, tokens int) error {
	if !s.cfg.Enabled {
		return nil
	}
	if s.repo == nil || tokens <= 0 {
		return nil
	}
	periodStart := currentPeriodStart(time.Now())
	newUsed, err := s.repo.IncrementUsed(ctx, tenantID, periodStart, int64(tokens))
	if err != nil {
		s.log.Error("budget increment failed",
			"tenant_id", tenantID, "tokens", tokens, "error", err)
		return fmt.Errorf("budget record: %w", err)
	}
	// Threshold-crossing notifications handled by a follow-up phase —
	// the last_warn/block_sent columns exist in the schema so the
	// outbox scheduler can notice a zero→non-zero transition and
	// emit a single notification idempotently. Phase 1 does not
	// emit them because the notification catalogue entry isn't wired
	// yet (RFC-008 §3.4).
	_ = newUsed
	return nil
}

// Status returns a read-model for UI / dashboard consumption. Works
// regardless of cfg.Enabled — admins need to see usage even before
// enforcement kicks in.
func (s *BudgetService) Status(ctx context.Context, tenantID shared.ID) (*BudgetStatus, error) {
	if s.repo == nil {
		return &BudgetStatus{TenantID: tenantID}, nil
	}
	row, err := s.fetchOrInitRow(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	st := &BudgetStatus{
		TenantID:    row.TenantID,
		PeriodStart: row.PeriodStart,
		PeriodEnd:   row.PeriodEnd,
		Limit:       row.TokenLimit,
		Used:        row.TokensUsed,
	}
	if row.TokenLimit > 0 {
		st.Remaining = row.TokenLimit - row.TokensUsed
		if st.Remaining < 0 {
			st.Remaining = 0
		}
		st.UsedPct = int((row.TokensUsed * 100) / row.TokenLimit)
		warnPct := row.WarnThresholdPct
		if warnPct == 0 {
			warnPct = s.cfg.DefaultWarnPct
		}
		warnAt := row.TokenLimit * int64(warnPct) / 100
		st.NeedsWarn = row.TokensUsed >= warnAt && row.LastWarnSentUsed < warnAt
	}
	return st, nil
}

// --- helpers ---------------------------------------------------------

func (s *BudgetService) fetchOrInitRow(ctx context.Context, tenantID shared.ID) (*BudgetRow, error) {
	now := time.Now()
	periodStart := currentPeriodStart(now)
	periodEnd := currentPeriodEnd(now)
	row, err := s.repo.GetOrCreate(ctx, tenantID, periodStart, periodEnd, s.cfg.DefaultTokensPerMonth)
	if err != nil {
		return nil, s.repoUnavailable(err.Error())
	}
	return row, nil
}

func (s *BudgetService) repoUnavailable(reason string) error {
	if s.cfg.Strict {
		return fmt.Errorf("%w: %s", ErrBudgetUnavailable, reason)
	}
	s.log.Warn("ai-triage budget repo unavailable; proceeding (non-strict mode)", "reason", reason)
	return nil
}

// currentPeriodStart returns the UTC midnight of the first day of the
// month containing t. The API deliberately uses UTC, not tenant-local
// time, because the billing period is platform-defined not tenant-
// defined. A tenant 12 hours east sees a "day shift" at end-of-month;
// documented in RFC-008 §3.1.
func currentPeriodStart(t time.Time) time.Time {
	t = t.UTC()
	return time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, time.UTC)
}

func currentPeriodEnd(t time.Time) time.Time {
	start := currentPeriodStart(t)
	return start.AddDate(0, 1, 0)
}

// estimateTokens gives a rough heuristic count for a prompt string.
// LLM providers differ, but ~4 characters per token is a reasonable
// upper bound that keeps our pre-check conservative (over-estimate
// is safe; under-estimate risks letting a single call overshoot the
// ceiling by up to MaxTokens). The post-call Record uses the actual
// count from the provider so the running counter stays accurate.
func estimateTokens(s string) int {
	if s == "" {
		return 0
	}
	return (len(s) + 3) / 4
}
