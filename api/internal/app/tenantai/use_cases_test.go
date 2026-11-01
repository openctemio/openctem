package tenantai

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	aidom "github.com/openctemio/openctem/api/pkg/domain/aianalysis"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// useCaseRepo adds the use case store to the settings fake, per tenant.
type useCaseRepo struct {
	*fakeRepo
	mu     sync.Mutex
	uc     map[shared.ID]aidom.UseCasePolicy
	stats  map[shared.ID]aidom.OverrideStats
	since  []time.Time
	saves  int
	racing bool // a change lands between the sweep's read and its write
}

func newUseCaseRepo() *useCaseRepo {
	return &useCaseRepo{fakeRepo: newFakeRepo(), uc: map[shared.ID]aidom.UseCasePolicy{}, stats: map[shared.ID]aidom.OverrideStats{}}
}

func (r *useCaseRepo) GetUseCases(_ context.Context, tid shared.ID) (aidom.UseCasePolicy, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := aidom.UseCasePolicy{}
	for k, v := range r.uc[tid] {
		out[k] = v
	}
	return out, nil
}

func (r *useCaseRepo) SaveUseCase(_ context.Context, tid shared.ID, uc aidom.UseCase, s aidom.UseCaseSetting) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.uc[tid] == nil {
		r.uc[tid] = aidom.UseCasePolicy{}
	}
	r.uc[tid][uc] = s
	r.saves++
	return nil
}

func (r *useCaseRepo) DowngradeUseCase(_ context.Context, tid shared.ID, uc aidom.UseCase, expected, next aidom.UseCaseSetting) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.racing || r.uc[tid][uc].Mode != expected.Mode {
		return false, nil
	}
	r.uc[tid][uc] = next
	return true, nil
}

func (r *useCaseRepo) ListAutoApply(context.Context, int) ([]aidom.AutoApplyUseCase, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []aidom.AutoApplyUseCase
	for tid, pol := range r.uc {
		for uc, s := range pol {
			if s.Mode == aidom.UseCaseAutoApply {
				out = append(out, aidom.AutoApplyUseCase{TenantID: tid, UseCase: uc, Setting: s})
			}
		}
	}
	return out, nil
}

func (r *useCaseRepo) OverrideStats(_ context.Context, tid shared.ID, _ aidom.UseCase, since time.Time, _ int) (aidom.OverrideStats, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.since = append(r.since, since)
	return r.stats[tid], nil
}

type stepUpGate struct {
	err   error
	calls int
}

func (g *stepUpGate) RequireRecentAuth(context.Context, string) error {
	g.calls++
	return g.err
}

type notifier struct{ n int }

func (n *notifier) NotifyPolicyLoosened(context.Context, string, auditapp.AuditContext, string, string, string) {
	n.n++
}

var errStepUp = errors.New("step-up required")

func newUseCaseHarness(t *testing.T) (*Service, *useCaseRepo, *stepUpGate, *notifier, shared.ID) {
	t.Helper()
	repo := newUseCaseRepo()
	svc := NewService(repo, nil, nil, nil, nil, nil)
	gate, note := &stepUpGate{}, &notifier{}
	svc.SetStepUpGate(gate)
	svc.SetLooseningNotifier(note)
	tid := shared.NewID()
	on := tenant.AISettings{}
	on.SetOptIn(true, "admin", time.Now())
	repo.rows[tid] = on
	return svc, repo, gate, note, tid
}

func TestUseCases_DefaultsAndConsent(t *testing.T) {
	svc, repo, _, _, tid := newUseCaseHarness(t)
	ctx := context.Background()
	list, err := svc.UseCases(ctx, tid.String())
	require.NoError(t, err)
	require.Len(t, list, 3)
	for i, uc := range aidom.UseCases() {
		require.Equal(t, uc, list[i].UseCase)
		require.Equal(t, aidom.UseCaseSuggest, list[i].Mode, "an untouched use case suggests")
		require.Equal(t, aidom.UseCaseSuggest, list[i].Effective)
		require.Equal(t, aidom.DataClassInternal, list[i].Ceiling)
		require.InDelta(t, 0.85, list[i].MinConfidence, 1e-9)
	}

	// AI turned off: every use case is off in force, whatever is saved.
	repo.rows[tid] = tenant.AISettings{}
	list, err = svc.UseCases(ctx, tid.String())
	require.NoError(t, err)
	for _, v := range list {
		require.Equal(t, aidom.UseCaseOff, v.Effective)
		require.Equal(t, aidom.UseCaseSuggest, v.Mode)
	}
}

// Auto-apply on and a ceiling above internal are loosenings: a recent
// sign-in, a named person, the owners told. Turning off is one click.
func TestSaveUseCase_LooseningNeedsStepUp(t *testing.T) {
	svc, repo, gate, note, tid := newUseCaseHarness(t)
	ctx := context.Background()

	gate.err = errStepUp
	_, err := svc.SaveUseCase(ctx, tid.String(), "triage", UseCaseInput{Mode: "auto_apply", Ceiling: "internal", MinConfidence: 0.9}, actx)
	require.ErrorIs(t, err, errStepUp)
	_, err = svc.SaveUseCase(ctx, tid.String(), "summary", UseCaseInput{Mode: "suggest", Ceiling: "restricted", MinConfidence: 0.85}, actx)
	require.ErrorIs(t, err, errStepUp)
	require.Zero(t, repo.saves, "a refused loosening writes nothing")

	// No actor: refused even with a gate that would pass.
	gate.err = nil
	_, err = svc.SaveUseCase(ctx, tid.String(), "triage", UseCaseInput{Mode: "auto_apply", Ceiling: "internal", MinConfidence: 0.9}, auditapp.AuditContext{})
	require.ErrorIs(t, err, ErrNoActor)

	v, err := svc.SaveUseCase(ctx, tid.String(), "triage", UseCaseInput{Mode: "auto_apply", Ceiling: "internal", MinConfidence: 0.9}, actx)
	require.NoError(t, err)
	require.Equal(t, []string{aidom.LoosenAutoApplyOn}, v.Loosened)
	require.NotNil(t, v.AutoApplySince)
	require.Equal(t, actx.ActorID, v.UpdatedBy)
	require.Equal(t, 1, note.n)

	// Tightening: no step-up asked even when the gate refuses.
	gate.err, gate.calls = errStepUp, 0
	v, err = svc.SaveUseCase(ctx, tid.String(), "triage", UseCaseInput{Mode: "off", Ceiling: "public", MinConfidence: 0.9}, actx)
	require.NoError(t, err)
	require.Empty(t, v.Loosened)
	require.Zero(t, gate.calls)
	require.Nil(t, v.AutoApplySince)
	require.Equal(t, aidom.UseCaseOff, repo.uc[tid][aidom.UseCaseTriage].Mode)
}

func TestSaveUseCase_Validation(t *testing.T) {
	svc, repo, _, _, tid := newUseCaseHarness(t)
	ctx := context.Background()
	bad := []struct {
		uc string
		in UseCaseInput
	}{
		{"chat", UseCaseInput{Mode: "suggest", Ceiling: "internal", MinConfidence: 0.85}},
		{"triage", UseCaseInput{Mode: "always", Ceiling: "internal", MinConfidence: 0.85}},
		{"triage", UseCaseInput{Mode: "suggest", Ceiling: "tenant_only", MinConfidence: 0.85}},
		{"triage", UseCaseInput{Mode: "suggest", Ceiling: "internal", MinConfidence: 0.3}},
	}
	for _, b := range bad {
		_, err := svc.SaveUseCase(ctx, tid.String(), b.uc, b.in, actx)
		require.ErrorIs(t, err, shared.ErrValidation, "%+v", b)
	}
	require.Zero(t, repo.saves)
}

// Each organization's settings are its own.
func TestUseCases_TenantIsolation(t *testing.T) {
	svc, repo, _, _, a := newUseCaseHarness(t)
	ctx := context.Background()
	b := shared.NewID()
	repo.rows[b] = repo.rows[a]
	_, err := svc.SaveUseCase(ctx, a.String(), "triage", UseCaseInput{Mode: "off", Ceiling: "public", MinConfidence: 0.85}, actx)
	require.NoError(t, err)
	got, err := svc.UseCaseSetting(ctx, b, aidom.UseCaseTriage)
	require.NoError(t, err)
	require.Equal(t, aidom.DefaultUseCaseSetting(), got)
}

// The sweep falls back a use case people overrode too often, counts only
// decisions since auto-apply was turned on, never overwrites a newer change,
// and turning auto-apply back on clears the downgrade.
func TestSweepUseCaseDowngrades(t *testing.T) {
	svc, repo, _, _, tid := newUseCaseHarness(t)
	ctx := context.Background()
	_, err := svc.SaveUseCase(ctx, tid.String(), "triage", UseCaseInput{Mode: "auto_apply", Ceiling: "internal", MinConfidence: 0.85}, actx)
	require.NoError(t, err)
	since := *repo.uc[tid][aidom.UseCaseTriage].AutoApplySince

	repo.stats[tid] = aidom.OverrideStats{Decisions: 10, Overrides: 1}
	n, err := svc.SweepUseCaseDowngrades(ctx)
	require.NoError(t, err)
	require.Zero(t, n)
	require.True(t, repo.since[0].Equal(since), "only decisions since auto-apply was turned on count")

	repo.stats[tid] = aidom.OverrideStats{Decisions: 10, Overrides: 2}
	repo.racing = true
	n, err = svc.SweepUseCaseDowngrades(ctx)
	require.NoError(t, err)
	require.Zero(t, n, "a setting changed since the read is left alone")

	repo.racing = false
	n, err = svc.SweepUseCaseDowngrades(ctx)
	require.NoError(t, err)
	require.Equal(t, 1, n)
	got := repo.uc[tid][aidom.UseCaseTriage]
	require.Equal(t, aidom.UseCaseSuggest, got.Mode)
	require.NotNil(t, got.DowngradedAt)
	require.Equal(t, aidom.DowngradeReasonOverrides, got.DowngradeReason)
	require.Equal(t, 2, got.DowngradeOverrides)
	require.Nil(t, got.AutoApplySince)

	v, err := svc.SaveUseCase(ctx, tid.String(), "triage", UseCaseInput{Mode: "auto_apply", Ceiling: "internal", MinConfidence: 0.85}, actx)
	require.NoError(t, err)
	require.Nil(t, v.DowngradedAt, "turning auto-apply back on clears the downgrade")
	require.Equal(t, []string{aidom.LoosenAutoApplyOn}, v.Loosened)
}
