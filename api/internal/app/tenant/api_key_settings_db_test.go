package tenant_test

import (
	"context"
	"errors"
	"sync"
	"testing"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	notificationdom "github.com/openctemio/openctem/api/pkg/domain/notification"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// keyPolicyAdmins answers the organization's owners and administrators;
// every other lifecycle method is unused here.
type keyPolicyAdmins struct {
	tenantdom.LifecycleRepository
	ids []shared.ID
}

func (a keyPolicyAdmins) ActiveAdminIDs(context.Context, shared.ID) ([]shared.ID, error) {
	return a.ids, nil
}

type keyPolicyInApp struct {
	mu     sync.Mutex
	titles []string
}

func (r *keyPolicyInApp) Notify(_ context.Context, p notificationdom.NotificationParams) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.titles = append(r.titles, p.Title)
	return nil
}

func (r *keyPolicyInApp) take() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := r.titles
	r.titles = nil
	return out
}

type keyPolicyGate struct{ err error }

func (g *keyPolicyGate) RequireRecentAuth(context.Context, string) error { return g.err }

var errKeyPolicyStepUp = errors.New("step up required")

// The organization's maximum API key lifetime against the real settings
// table: 90 days by default; a shorter maximum needs no step-up and tells
// nobody; a longer one is refused on an old sign-in (nothing saved), then
// saved with a fresh one and every owner and administrator is told; the
// platform ceiling is never exceeded. Requires DATABASE_URL.
func TestAPIKeyPolicy_TightenFreeLoosenNeedsStepUp(t *testing.T) {
	f := newSettingsFixture(t)
	ctx := context.Background()
	tid := shared.MustIDFromString(f.tenantID)
	inApp := &keyPolicyInApp{}
	f.svc.SetLifecycleRepository(keyPolicyAdmins{ids: []shared.ID{shared.NewID(), shared.NewID()}})
	f.svc.SetLifecycleNotifier(inApp)
	gate := &keyPolicyGate{err: errKeyPolicyStepUp}
	f.svc.SetStepUpGate(gate)
	actx := auditapp.AuditContext{ActorID: shared.NewID().String()}

	if n, err := f.svc.MaxAPIKeyLifetimeDays(ctx, tid); err != nil || n != tenantdom.DefaultAPIKeyMaxLifetimeDays {
		t.Fatalf("default = %d %v, want %d", n, err, tenantdom.DefaultAPIKeyMaxLifetimeDays)
	}

	// Tighten on an old sign-in: allowed, nobody told.
	if _, err := f.svc.UpdateAPIKeySettings(ctx, f.tenantID, tenantdom.APIKeySettings{MaxLifetimeDays: 30}, actx); err != nil {
		t.Fatalf("tighten: %v", err)
	}
	if n, _ := f.svc.MaxAPIKeyLifetimeDays(ctx, tid); n != 30 {
		t.Fatalf("after tighten = %d, want 30", n)
	}
	if got := inApp.take(); len(got) != 0 {
		t.Fatalf("tightening notified: %v", got)
	}

	// Loosen on an old sign-in: refused, nothing saved.
	if _, err := f.svc.UpdateAPIKeySettings(ctx, f.tenantID, tenantdom.APIKeySettings{MaxLifetimeDays: 200}, actx); !errors.Is(err, errKeyPolicyStepUp) {
		t.Fatalf("loosen with an old sign-in: err = %v, want step-up", err)
	}
	if n, _ := f.svc.MaxAPIKeyLifetimeDays(ctx, tid); n != 30 {
		t.Fatalf("refused loosening was saved: %d", n)
	}
	// Without an acting person a loosening is refused.
	if _, err := f.svc.UpdateAPIKeySettings(ctx, f.tenantID, tenantdom.APIKeySettings{MaxLifetimeDays: 200}, auditapp.AuditContext{}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("loosen without an actor: err = %v", err)
	}

	// Loosen with a fresh sign-in: saved, owners and administrators told.
	gate.err = nil
	if _, err := f.svc.UpdateAPIKeySettings(ctx, f.tenantID, tenantdom.APIKeySettings{MaxLifetimeDays: 200}, actx); err != nil {
		t.Fatalf("loosen with step-up: %v", err)
	}
	if got := inApp.take(); len(got) != 2 || got[0] != "API key lifetime raised" {
		t.Fatalf("loosening notices = %v, want two", got)
	}

	// Above the platform ceiling: refused whoever asks.
	if _, err := f.svc.UpdateAPIKeySettings(ctx, f.tenantID, tenantdom.APIKeySettings{MaxLifetimeDays: tenantdom.APIKeyLifetimeCeilingDays + 1}, actx); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("above the ceiling: err = %v, want validation", err)
	}
}
