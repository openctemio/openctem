package aitriage

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

// budgetRepoMock is a minimal BudgetRepository for unit tests.
// Tracks Increment calls so we can assert Record() actually ran.
type budgetRepoMock struct {
	row            *BudgetRow
	incrementCalls int
	incrementDelta int64
	incrementErr   error
	getErr         error
}

func (m *budgetRepoMock) GetOrCreate(_ context.Context, tenantID shared.ID, ps, pe time.Time, defaultLimit int64) (*BudgetRow, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	if m.row != nil {
		return m.row, nil
	}
	// Fresh default row matches the schema's upsert semantics.
	return &BudgetRow{
		TenantID:          tenantID,
		PeriodStart:       ps,
		PeriodEnd:         pe,
		TokenLimit:        defaultLimit,
		TokensUsed:        0,
		LastWarnSentUsed:  -1,
		LastBlockSentUsed: -1,
	}, nil
}

func (m *budgetRepoMock) IncrementUsed(_ context.Context, _ shared.ID, _ time.Time, delta int64) (int64, error) {
	m.incrementCalls++
	m.incrementDelta += delta
	if m.incrementErr != nil {
		return 0, m.incrementErr
	}
	if m.row != nil {
		m.row.TokensUsed += delta
		return m.row.TokensUsed, nil
	}
	return delta, nil
}

func (m *budgetRepoMock) UpdateLastWarnSent(_ context.Context, _ shared.ID, _ time.Time, _ int64) error {
	return nil
}

func (m *budgetRepoMock) UpdateLastBlockSent(_ context.Context, _ shared.ID, _ time.Time, _ int64) error {
	return nil
}

func nopLog() *logger.Logger { return logger.NewNop() }
func newTenantID() shared.ID { return shared.NewID() }

// ---- Flag OFF: every method is a no-op, repo is never touched.

func TestBudgetService_Disabled_CheckSkipsRepo(t *testing.T) {
	repo := &budgetRepoMock{}
	svc := NewBudgetService(repo, BudgetServiceConfig{Enabled: false}, nopLog())

	if err := svc.Check(context.Background(), newTenantID(), 1000); err != nil {
		t.Fatalf("Check() when disabled must return nil, got %v", err)
	}
	if repo.incrementCalls != 0 {
		t.Errorf("Record() when disabled must not touch repo, got %d increment calls", repo.incrementCalls)
	}
}

func TestBudgetService_Disabled_RecordSkipsRepo(t *testing.T) {
	repo := &budgetRepoMock{}
	svc := NewBudgetService(repo, BudgetServiceConfig{Enabled: false}, nopLog())
	if err := svc.Record(context.Background(), newTenantID(), 500); err != nil {
		t.Fatalf("Record() when disabled must return nil, got %v", err)
	}
	if repo.incrementCalls != 0 {
		t.Errorf("Record() when disabled must not increment, got %d calls", repo.incrementCalls)
	}
}

// ---- Flag ON: enforcement semantics.

func TestBudgetService_Enabled_UnlimitedPasses(t *testing.T) {
	repo := &budgetRepoMock{row: &BudgetRow{TokenLimit: 0, TokensUsed: 99999}}
	svc := NewBudgetService(repo, BudgetServiceConfig{Enabled: true}, nopLog())
	if err := svc.Check(context.Background(), newTenantID(), 100000); err != nil {
		t.Errorf("TokenLimit=0 means unlimited; Check must pass, got %v", err)
	}
}

func TestBudgetService_Enabled_UnderLimit(t *testing.T) {
	repo := &budgetRepoMock{row: &BudgetRow{TokenLimit: 1000, TokensUsed: 100, BlockThresholdPct: 100}}
	svc := NewBudgetService(repo, BudgetServiceConfig{Enabled: true}, nopLog())
	if err := svc.Check(context.Background(), newTenantID(), 50); err != nil {
		t.Errorf("100+50 < 1000; Check must pass, got %v", err)
	}
}

func TestBudgetService_Enabled_OverBlockThreshold(t *testing.T) {
	repo := &budgetRepoMock{row: &BudgetRow{TokenLimit: 1000, TokensUsed: 950, BlockThresholdPct: 100}}
	svc := NewBudgetService(repo, BudgetServiceConfig{Enabled: true}, nopLog())

	err := svc.Check(context.Background(), newTenantID(), 100)
	if err == nil {
		t.Fatal("950+100 >= 1000 should trigger ErrBudgetExceeded")
	}
	if !errors.Is(err, ErrBudgetExceeded) {
		t.Errorf("expected ErrBudgetExceeded, got %v", err)
	}
}

// Soft-threshold (block_threshold_pct < 100) — some tenants block at
// 90% to leave headroom. Pin that the service respects per-row pct
// rather than the 100% default.
func TestBudgetService_Enabled_RespectsSoftBlockThreshold(t *testing.T) {
	repo := &budgetRepoMock{row: &BudgetRow{TokenLimit: 1000, TokensUsed: 850, BlockThresholdPct: 90}}
	svc := NewBudgetService(repo, BudgetServiceConfig{Enabled: true}, nopLog())

	err := svc.Check(context.Background(), newTenantID(), 100)
	if err == nil {
		t.Fatal("tokens_used+est=950 >= 1000*90/100=900 should block")
	}
	if !errors.Is(err, ErrBudgetExceeded) {
		t.Errorf("expected ErrBudgetExceeded, got %v", err)
	}
}

// Repo error, strict=false → Check returns nil (non-strict fail-open).
// This is the dev/staging default so a transient DB blip doesn't
// stall triage.
func TestBudgetService_RepoError_NonStrict_PassesThrough(t *testing.T) {
	repo := &budgetRepoMock{getErr: errors.New("db blip")}
	svc := NewBudgetService(repo, BudgetServiceConfig{Enabled: true, Strict: false}, nopLog())

	if err := svc.Check(context.Background(), newTenantID(), 500); err != nil {
		t.Errorf("non-strict mode must pass through on repo error, got %v", err)
	}
}

// Repo error, strict=true → Check returns ErrBudgetUnavailable.
// Production default per RFC-008 §3.5.
func TestBudgetService_RepoError_Strict_FailsClosed(t *testing.T) {
	repo := &budgetRepoMock{getErr: errors.New("db blip")}
	svc := NewBudgetService(repo, BudgetServiceConfig{Enabled: true, Strict: true}, nopLog())

	err := svc.Check(context.Background(), newTenantID(), 500)
	if err == nil {
		t.Fatal("strict mode must fail on repo error")
	}
	if !errors.Is(err, ErrBudgetUnavailable) {
		t.Errorf("expected ErrBudgetUnavailable, got %v", err)
	}
}

// Record() calls must be idempotent (caller may retry). The repo's
// atomic UPDATE handles the actual idempotency; this test pins that
// Record passes through the delta without mutation.
func TestBudgetService_Enabled_RecordPassesDelta(t *testing.T) {
	repo := &budgetRepoMock{}
	svc := NewBudgetService(repo, BudgetServiceConfig{Enabled: true}, nopLog())

	if err := svc.Record(context.Background(), newTenantID(), 1234); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if repo.incrementCalls != 1 || repo.incrementDelta != 1234 {
		t.Errorf("expected 1 increment of 1234 tokens, got calls=%d delta=%d",
			repo.incrementCalls, repo.incrementDelta)
	}
}

// Record ignores non-positive token counts defensively — if the LLM
// provider response fails to populate token fields we don't want
// negative deltas corrupting the counter.
func TestBudgetService_Record_IgnoresNonPositiveTokens(t *testing.T) {
	repo := &budgetRepoMock{}
	svc := NewBudgetService(repo, BudgetServiceConfig{Enabled: true}, nopLog())
	_ = svc.Record(context.Background(), newTenantID(), 0)
	_ = svc.Record(context.Background(), newTenantID(), -5)
	if repo.incrementCalls != 0 {
		t.Errorf("non-positive tokens must not touch repo, got %d calls", repo.incrementCalls)
	}
}

// Status returns the read model even when budget is disabled — UI
// needs to show usage before enforcement kicks in.
func TestBudgetService_Status_WorksWhenDisabled(t *testing.T) {
	repo := &budgetRepoMock{row: &BudgetRow{TokenLimit: 1000, TokensUsed: 400}}
	svc := NewBudgetService(repo, BudgetServiceConfig{Enabled: false}, nopLog())

	st, err := svc.Status(context.Background(), newTenantID())
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if st.Used != 400 || st.Limit != 1000 || st.Remaining != 600 {
		t.Errorf("status mismatch: %+v", st)
	}
	if st.UsedPct != 40 {
		t.Errorf("used_pct: want 40, got %d", st.UsedPct)
	}
}

func TestBudgetService_Status_NeedsWarnAfterThreshold(t *testing.T) {
	// 80% threshold default, used = 850 over limit 1000 → 85% → needs warn
	repo := &budgetRepoMock{row: &BudgetRow{
		TokenLimit:       1000,
		TokensUsed:       850,
		LastWarnSentUsed: -1, // never emitted
	}}
	svc := NewBudgetService(repo, BudgetServiceConfig{Enabled: true}, nopLog())

	st, err := svc.Status(context.Background(), newTenantID())
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if !st.NeedsWarn {
		t.Errorf("expected NeedsWarn=true at 85%% usage with no prior warn")
	}
}

func TestBudgetService_Status_AlreadyWarnedSkipsNeedsWarn(t *testing.T) {
	// Same crossing, but last_warn_sent_used already past the warn
	// point → don't re-emit.
	repo := &budgetRepoMock{row: &BudgetRow{
		TokenLimit:       1000,
		TokensUsed:       850,
		LastWarnSentUsed: 800, // ≥ 80% * 1000, so already sent
	}}
	svc := NewBudgetService(repo, BudgetServiceConfig{Enabled: true}, nopLog())

	st, err := svc.Status(context.Background(), newTenantID())
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if st.NeedsWarn {
		t.Errorf("NeedsWarn should stay false after emission; last_warn_sent=%d", repo.row.LastWarnSentUsed)
	}
}

// currentPeriodStart / End invariants: start is first of month UTC,
// end is start + 1 month.
func TestBudgetPeriod_MonthBoundaries(t *testing.T) {
	cases := []struct {
		in, wantStart, wantEnd string
	}{
		{"2026-04-22T10:00:00Z", "2026-04-01T00:00:00Z", "2026-05-01T00:00:00Z"},
		{"2026-12-31T23:59:59Z", "2026-12-01T00:00:00Z", "2027-01-01T00:00:00Z"},
		{"2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z", "2026-02-01T00:00:00Z"},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			in, _ := time.Parse(time.RFC3339, tc.in)
			if got := currentPeriodStart(in).Format(time.RFC3339); got != tc.wantStart {
				t.Errorf("currentPeriodStart(%s) = %s, want %s", tc.in, got, tc.wantStart)
			}
			if got := currentPeriodEnd(in).Format(time.RFC3339); got != tc.wantEnd {
				t.Errorf("currentPeriodEnd(%s) = %s, want %s", tc.in, got, tc.wantEnd)
			}
		})
	}
}

func TestEstimateTokens_RoughHeuristic(t *testing.T) {
	// Conservative: ~4 chars/token, round up.
	cases := []struct {
		in   string
		want int
	}{
		{"", 0},
		{"a", 1},
		{"abcd", 1},
		{"abcde", 2},
		{"12345678", 2},
		{"123456789", 3},
	}
	for _, tc := range cases {
		if got := estimateTokens(tc.in); got != tc.want {
			t.Errorf("estimateTokens(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}
