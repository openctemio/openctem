package postgres

import (
	"context"
	"errors"
	"testing"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/tenantai"
	"github.com/openctemio/openctem/api/pkg/crypto"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
)

type autoTriageGate struct{ err error }

func (g *autoTriageGate) RequireRecentAuth(context.Context, string) error { return g.err }

type autoTriageNotices struct{ titles []string }

func (n *autoTriageNotices) NotifyPolicyLoosened(_ context.Context, _ string, _ auditapp.AuditContext, title, _, _ string) {
	n.titles = append(n.titles, title)
}

var errAutoTriageStepUp = errors.New("step up required")

// The automatic AI triage policy through the service and the real table:
// a loosening (on, a severity added) is refused without a recent sign-in and
// nothing is stored; with one it is stored, owners and administrators are
// told; tightening needs no sign-in and tells nobody; an explicit "off" wins
// over a platform default that is on; another organization is untouched and
// no consent is created. Requires DATABASE_URL.
func TestAutoTriagePolicy_LooseningNeedsStepUp(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	repo := NewTenantAISettingsRepository(&DB{DB: sqlDB})

	a, b := shared.NewID(), shared.NewID()
	for _, id := range []shared.ID{a, b} {
		if _, err := sqlDB.ExecContext(ctx, `INSERT INTO tenants (id, name, slug) VALUES ($1, 'auto triage', $2)`, id.String(), "tat-"+id.String()); err != nil {
			t.Fatal(err)
		}
		id := id
		t.Cleanup(func() {
			_, _ = sqlDB.ExecContext(context.Background(), `DELETE FROM tenants WHERE id = $1`, id.String())
		})
	}

	gate, notices := &autoTriageGate{err: errAutoTriageStepUp}, &autoTriageNotices{}
	svc := tenantai.NewService(repo, crypto.NewNoOpEncryptor(), nil, nil, nil, nil)
	svc.SetStepUpGate(gate)
	svc.SetLooseningNotifier(notices)
	// Platform default: off, critical (the shipped default severities).
	svc.SetAutoTriageDefaults(func() tenant.AISettings {
		return tenant.AISettings{AutoTriageSeverities: []string{"critical", "high"}, AutoTriageDelaySeconds: 60}
	})
	actx := auditapp.AuditContext{ActorID: shared.NewID().String()}

	// Old sign-in: turning it on is refused and nothing is stored.
	on := tenant.AutoTriagePolicy{Enabled: true, Severities: []string{"critical"}, DelaySeconds: 30}
	if _, err := svc.SaveAutoTriage(ctx, a.String(), on, actx); !errors.Is(err, errAutoTriageStepUp) {
		t.Fatalf("turning on with an old sign-in: err = %v, want step-up", err)
	}
	if got, _ := svc.GetAutoTriage(ctx, a.String()); got.Enabled {
		t.Fatal("refused loosening was stored")
	}
	if len(notices.titles) != 0 {
		t.Fatalf("refused loosening notified: %v", notices.titles)
	}
	// Without an acting person a loosening is refused even with no gate.
	if _, err := svc.SaveAutoTriage(ctx, a.String(), on, auditapp.AuditContext{}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("loosening without an actor: err = %v, want validation", err)
	}

	// Fresh sign-in: stored, loosened, owners and administrators told.
	gate.err = nil
	v, err := svc.SaveAutoTriage(ctx, a.String(), on, actx)
	if err != nil || !v.Loosened {
		t.Fatalf("turning on with a fresh sign-in: %+v %v", v, err)
	}
	if len(notices.titles) != 1 {
		t.Fatalf("notices = %v, want one", notices.titles)
	}
	got, err := svc.GetAutoTriage(ctx, a.String())
	if err != nil || !got.Enabled || len(got.Severities) != 1 || got.Severities[0] != "critical" || got.DelaySeconds != 30 {
		t.Fatalf("stored policy = %+v %v", got, err)
	}
	// The row carries no consent: AI triage itself stays off.
	if s, err := repo.Get(ctx, a, tenant.AISettings{}); err != nil || s.OptedIn() {
		t.Fatalf("saving the policy must not turn AI triage on: %+v %v", s, err)
	}

	// Old sign-in again: adding a severity is refused, nothing stored.
	gate.err = errAutoTriageStepUp
	wider := tenant.AutoTriagePolicy{Enabled: true, Severities: []string{"critical", "medium"}, DelaySeconds: 30}
	if _, err := svc.SaveAutoTriage(ctx, a.String(), wider, actx); !errors.Is(err, errAutoTriageStepUp) {
		t.Fatalf("adding a severity: err = %v, want step-up", err)
	}
	if got, _ := svc.GetAutoTriage(ctx, a.String()); len(got.Severities) != 1 {
		t.Fatalf("refused widening was stored: %+v", got)
	}

	// Tightening and the delay need no sign-in and tell nobody.
	if v, err := svc.SaveAutoTriage(ctx, a.String(), tenant.AutoTriagePolicy{Enabled: true, Severities: []string{"critical"}, DelaySeconds: 0}, actx); err != nil || v.Loosened {
		t.Fatalf("shorter delay: %+v %v", v, err)
	}
	if _, err := svc.SaveAutoTriage(ctx, a.String(), tenant.AutoTriagePolicy{Enabled: false, Severities: []string{"critical", "high", "medium"}}, actx); err != nil {
		t.Fatalf("turning off: %v", err)
	}
	if len(notices.titles) != 1 {
		t.Fatalf("tightening notified: %v", notices.titles)
	}

	// An explicit off wins over a platform default that is on.
	svc.SetAutoTriageDefaults(func() tenant.AISettings {
		return tenant.AISettings{AutoTriageEnabled: true, AutoTriageSeverities: []string{"critical"}}
	})
	if got, _ := svc.GetAutoTriage(ctx, a.String()); got.Enabled {
		t.Fatal("a saved off must win over the platform default")
	}
	// The other organization still follows the default and has no row.
	if got, _ := svc.GetAutoTriage(ctx, b.String()); !got.Enabled {
		t.Fatalf("organization b must keep the platform default: %+v", got)
	}
	var n int
	if err := sqlDB.QueryRowContext(ctx, `SELECT count(*) FROM tenant_ai_settings WHERE tenant_id = $1`, b.String()).Scan(&n); err != nil || n != 0 {
		t.Fatalf("organization b rows = %d %v, want 0", n, err)
	}
}
