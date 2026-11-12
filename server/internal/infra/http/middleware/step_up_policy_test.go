package middleware

// The organization's re-verification policy (docs/architecture/step-up-reauth.md):
// tiers, modes, windows, the every_time spend, the interactive-only rule and
// tenant isolation of the policy read.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/stepup"
)

// policyStore is a per-tenant policy provider.
type policyStore struct {
	byTenant map[string]stepup.Policy
	reads    []string
	err      error
}

func (p *policyStore) StepUpPolicy(_ context.Context, tenantID string) (stepup.Policy, error) {
	p.reads = append(p.reads, tenantID)
	if p.err != nil {
		return stepup.Policy{}, p.err
	}
	if pol, ok := p.byTenant[tenantID]; ok {
		return pol, nil
	}
	return stepup.LegacyPolicy(), nil
}

// sessionProofs is one session's proof and the proof last spent, with the
// store's every_time semantics.
type sessionProofs struct {
	mu    sync.Mutex
	at    time.Time
	spent time.Time
}

func (s *sessionProofs) RecentAuthAt(context.Context, string, string) (time.Time, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.at, nil
}

func (s *sessionProofs) SpendRecentAuth(_ context.Context, _, _ string, notBefore time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.at.Before(notBefore) || !s.spent.Before(s.at) {
		return false, nil
	}
	s.spent = s.at
	return true, nil
}

func sessionCtx(tenantID string) context.Context {
	ctx := context.WithValue(context.Background(), UserIDKey, "u1")
	ctx = context.WithValue(ctx, SessionIDKey, "s1")
	ctx = context.WithValue(ctx, TenantIDKey, tenantID)
	return stepup.WithRequestState(ctx)
}

func policyWith(mut func(*stepup.Policy)) stepup.Policy {
	p := stepup.LegacyPolicy()
	mut(&p)
	return p
}

func TestCheckStepUp_RoutineOffNeedsNoProof(t *testing.T) {
	proofs := &sessionProofs{at: time.Now().Add(-48 * time.Hour)}
	pol := &policyStore{byTenant: map[string]stepup.Policy{"t1": stepup.DefaultPolicy()}}
	ctx := sessionCtx("t1")
	if err := CheckStepUp(ctx, proofs, pol, stepup.TierRoutine); err != nil {
		t.Fatalf("routine off: %v", err)
	}
	if a, ok := stepup.StateFrom(ctx).Strictest(); !ok || a.Mode != stepup.ModeOff || a.Tier != stepup.TierRoutine {
		t.Errorf("the applied rule must be recorded for the audit trail, got %+v %v", a, ok)
	}
}

func TestCheckStepUp_CriticalStillAsks(t *testing.T) {
	proofs := &sessionProofs{at: time.Now().Add(-11 * time.Minute)}
	off := policyWith(func(p *stepup.Policy) { p.Sensitive = stepup.Rule{Mode: stepup.ModeOff} })
	pol := &policyStore{byTenant: map[string]stepup.Policy{"t1": off}}
	err := CheckStepUp(sessionCtx("t1"), proofs, pol, stepup.TierCritical)
	var req *StepUpRequiredError
	if !errors.As(err, &req) || !errors.Is(err, ErrStepUpRequired) || req.Tier != stepup.TierCritical {
		t.Fatalf("critical with a stale proof: got %v", err)
	}
	if err := CheckStepUp(sessionCtx("t1"), proofs, pol, stepup.TierSensitive); err != nil {
		t.Fatalf("sensitive off: %v", err)
	}
}

func TestCheckStepUp_Windows(t *testing.T) {
	for _, tc := range []struct {
		window string
		age    time.Duration
		want   error
	}{
		{stepup.Window10m, 9 * time.Minute, nil},
		{stepup.Window10m, 11 * time.Minute, ErrStepUpRequired},
		{stepup.Window1h, 50 * time.Minute, nil},
		{stepup.Window1h, 61 * time.Minute, ErrStepUpRequired},
		{stepup.Window8h, 7 * time.Hour, nil},
		{stepup.WindowSession, 72 * time.Hour, nil},
	} {
		proofs := &sessionProofs{at: time.Now().Add(-tc.age)}
		pol := &policyStore{byTenant: map[string]stepup.Policy{"t1": policyWith(func(p *stepup.Policy) {
			p.Sensitive = stepup.Rule{Mode: stepup.ModeWindow, Window: tc.window}
		})}}
		err := CheckStepUp(sessionCtx("t1"), proofs, pol, stepup.TierSensitive)
		if !errors.Is(err, tc.want) || (tc.want == nil && err != nil) {
			t.Errorf("window %s, proof %s old: got %v, want %v", tc.window, tc.age, err, tc.want)
		}
	}
	// The session window still needs a proof: the store's epoch means none.
	pol := &policyStore{byTenant: map[string]stepup.Policy{"t1": policyWith(func(p *stepup.Policy) {
		p.Sensitive = stepup.Rule{Mode: stepup.ModeWindow, Window: stepup.WindowSession}
	})}}
	if err := CheckStepUp(sessionCtx("t1"), &sessionProofs{at: time.Unix(0, 0)}, pol, stepup.TierSensitive); !errors.Is(err, ErrStepUpRequired) {
		t.Errorf("session window without a proof: got %v", err)
	}
}

// One proof unlocks a window for many actions until it expires.
func TestCheckStepUp_WindowReuseAndExpiry(t *testing.T) {
	proofs := &sessionProofs{at: time.Now().Add(-5 * time.Minute)}
	pol := &policyStore{}
	for i := 0; i < 3; i++ {
		if err := CheckStepUp(sessionCtx("t1"), proofs, pol, stepup.TierSensitive); err != nil {
			t.Fatalf("action %d inside the window: %v", i, err)
		}
	}
	proofs.at = time.Now().Add(-10*time.Minute - time.Second)
	if err := CheckStepUp(sessionCtx("t1"), proofs, pol, stepup.TierSensitive); !errors.Is(err, ErrStepUpRequired) {
		t.Fatalf("after the window: got %v", err)
	}
}

func TestCheckStepUp_EveryTimeSpendsOneProof(t *testing.T) {
	proofs := &sessionProofs{at: time.Now().Add(-time.Minute)}
	pol := &policyStore{byTenant: map[string]stepup.Policy{"t1": policyWith(func(p *stepup.Policy) {
		p.Critical = stepup.Rule{Mode: stepup.ModeEveryTime}
	})}}
	first := sessionCtx("t1")
	if err := CheckStepUp(first, proofs, pol, stepup.TierCritical); err != nil {
		t.Fatalf("first action: %v", err)
	}
	// A second gate in the same request shares the spend.
	if err := CheckStepUp(first, proofs, pol, stepup.TierCritical); err != nil {
		t.Fatalf("second gate in the same request: %v", err)
	}
	// The next request needs a new proof.
	err := CheckStepUp(sessionCtx("t1"), proofs, pol, stepup.TierCritical)
	var req *StepUpRequiredError
	if !errors.As(err, &req) || req.Rule.Mode != stepup.ModeEveryTime {
		t.Fatalf("second action: got %v", err)
	}
	proofs.mu.Lock()
	proofs.at = time.Now()
	proofs.mu.Unlock()
	if err := CheckStepUp(sessionCtx("t1"), proofs, pol, stepup.TierCritical); err != nil {
		t.Fatalf("after a new proof: %v", err)
	}
	// A proof older than the freshness cannot be spent.
	proofs.mu.Lock()
	proofs.at, proofs.spent = time.Now().Add(-stepup.EveryTimeFreshness-time.Second), time.Time{}
	proofs.mu.Unlock()
	if err := CheckStepUp(sessionCtx("t1"), proofs, pol, stepup.TierCritical); !errors.Is(err, ErrStepUpRequired) {
		t.Fatalf("stale proof: got %v", err)
	}
}

func TestCheckStepUp_EveryTimeWithoutSpenderIsUnavailable(t *testing.T) {
	pol := &policyStore{byTenant: map[string]stepup.Policy{"t1": policyWith(func(p *stepup.Policy) {
		p.Critical = stepup.Rule{Mode: stepup.ModeEveryTime}
	})}}
	if err := CheckStepUp(sessionCtx("t1"), &stubRecentAuth{at: time.Now()}, pol, stepup.TierCritical); !errors.Is(err, ErrStepUpUnavailable) {
		t.Fatalf("got %v", err)
	}
}

func TestCheckStepUp_APIKeys(t *testing.T) {
	keyCtx := func() context.Context {
		ctx := context.WithValue(context.Background(), UserIDKey, "u1")
		ctx = context.WithValue(ctx, TenantIDKey, "t1")
		return context.WithValue(ctx, APIKeyIDKey, "k1")
	}
	routineOn := &policyStore{byTenant: map[string]stepup.Policy{"t1": policyWith(func(p *stepup.Policy) {
		p.Routine = stepup.Rule{Mode: stepup.ModeEveryTime}
		p.Sensitive = stepup.Rule{Mode: stepup.ModeOff}
	})}}
	if err := CheckStepUp(keyCtx(), &sessionProofs{}, routineOn, stepup.TierRoutine); err != nil {
		t.Errorf("routine never refuses an API key: %v", err)
	}
	if len(routineOn.reads) != 0 {
		t.Error("routine for an API key needs no policy read")
	}
	for _, tier := range []stepup.Tier{stepup.TierSensitive, stepup.TierCritical} {
		if err := CheckStepUp(keyCtx(), &sessionProofs{}, routineOn, tier); !errors.Is(err, ErrStepUpUnavailable) {
			t.Errorf("%s stays interactive-only even when off: got %v", tier, err)
		}
	}
}

// Tenant isolation: the policy is the one of the organization the request
// acts in, never another organization's.
func TestCheckStepUp_ReadsTheRequestsOrganization(t *testing.T) {
	stale := &sessionProofs{at: time.Now().Add(-2 * time.Hour)}
	pol := &policyStore{byTenant: map[string]stepup.Policy{
		"t-off": policyWith(func(p *stepup.Policy) { p.Sensitive = stepup.Rule{Mode: stepup.ModeOff} }),
	}}
	if err := CheckStepUp(sessionCtx("t-off"), stale, pol, stepup.TierSensitive); err != nil {
		t.Fatalf("own organization, sensitive off: %v", err)
	}
	if err := CheckStepUp(sessionCtx("t-strict"), stale, pol, stepup.TierSensitive); !errors.Is(err, ErrStepUpRequired) {
		t.Fatalf("another organization must not inherit the off policy: got %v", err)
	}
	// A /tenants/{tenant} route acts in the URL organization (membership
	// checked), not the token's.
	team := shared.NewID()
	pol.byTenant[team.String()] = stepup.LegacyPolicy()
	ctx := context.WithValue(sessionCtx("t-off"), TeamIDKey, team)
	if err := CheckStepUp(ctx, stale, pol, stepup.TierSensitive); !errors.Is(err, ErrStepUpRequired) {
		t.Fatalf("URL organization policy: got %v", err)
	}
	if pol.reads[len(pol.reads)-1] != team.String() {
		t.Errorf("read %v, want the URL organization", pol.reads)
	}
}

func TestCheckStepUp_PolicyReadErrorFailsClosed(t *testing.T) {
	boom := errors.New("db down")
	err := CheckStepUp(sessionCtx("t1"), &sessionProofs{at: time.Now()}, &policyStore{err: boom}, stepup.TierRoutine)
	if !errors.Is(err, boom) {
		t.Fatalf("got %v", err)
	}
}

func TestRequireStepUp_ErrorDetails(t *testing.T) {
	pol := &policyStore{byTenant: map[string]stepup.Policy{"t1": policyWith(func(p *stepup.Policy) {
		p.Sensitive = stepup.Rule{Mode: stepup.ModeWindow, Window: stepup.Window1h}
	})}}
	h := RequireStepUp(&sessionProofs{at: time.Now().Add(-2 * time.Hour)}, pol, stepup.TierSensitive)(
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("must not reach the handler") }))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequestWithContext(sessionCtx("t1"), http.MethodPost, "/", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status %d", rec.Code)
	}
	var body struct {
		Code    string         `json:"code"`
		Details map[string]any `json:"details"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Code != string(CodeStepUpRequired) || body.Details["tier"] != "sensitive" || body.Details["mode"] != "once_per_window" ||
		body.Details["window"] != "1h" || body.Details["window_seconds"] != float64(3600) {
		t.Fatalf("body %s", rec.Body.String())
	}
}
