package integration

import (
	"context"
	"errors"
	"sync"
	"testing"

	cirunapp "github.com/openctemio/openctem/api/internal/app/cirun"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/cirun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// alertRecorder records admin alerts.
type alertRecorder struct {
	mu  sync.Mutex
	got []cirunapp.AdminAlert
}

func (a *alertRecorder) AlertAdmins(_ context.Context, _ shared.ID, al cirunapp.AdminAlert) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.got = append(a.got, al)
}

func (a *alertRecorder) count() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.got)
}

var errNeedsStepUp = errors.New("step-up required (test)")

// A gate policy change that lets more findings pass needs step-up and is
// audited at high severity and announced to the administrators, like a
// break-glass; a change that tightens the gate needs neither.
func TestCIGatePolicy_LooseningNeedsStepUpAndIsAnnounced(t *testing.T) {
	alerts := &alertRecorder{}
	r := newCIRigWith(t, cirunapp.Config{}, func(d *cirunapp.Deps) { d.Alerts = alerts })
	ctx := context.Background()
	uid := shared.NewID()
	if _, err := r.db.ExecContext(ctx, `INSERT INTO users (id, email, name) VALUES ($1, $2, 'CI admin')`,
		uid.String(), uid.String()+"@loosen.test"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = r.db.ExecContext(context.Background(), `DELETE FROM users WHERE id = $1`, uid.String()) })
	admin := cirunapp.Actor{UserID: uid.String(), Email: "admin@acme.test"}

	repoAsset, err := asset.NewAsset("github.com/acme/loosen-"+shared.NewID().String()[:8], asset.AssetTypeRepository, asset.CriticalityMedium)
	if err != nil {
		t.Fatal(err)
	}
	repoAsset.SetTenantID(r.tenant)
	if err := postgres.NewAssetRepository(r.db).Create(ctx, repoAsset); err != nil {
		t.Fatal(err)
	}
	repoID := repoAsset.ID()

	// Tightening the organization policy (medium, every finding): no step-up.
	r.svc.SetStepUpGate(recentAuth{err: errNeedsStepUp})
	no := false
	org, err := r.svc.CreateGatePolicy(ctx, r.tenant, cirunapp.GatePolicyInput{ScopeType: cirun.ScopeTenant,
		FailOnSeverity: "medium", NewFindingsOnly: &no}, admin)
	if err != nil {
		t.Fatalf("tightening asked for step-up: %v", err)
	}
	if alerts.count() != 0 || r.auditCount(r.tenant, "ci_gate_policy.loosened", "") != 0 {
		t.Fatal("tightening was announced as loosening")
	}

	// A repository policy looser than the organization's (high) needs it.
	looser := cirunapp.GatePolicyInput{ScopeType: cirun.ScopeRepository, ScopeID: &repoID, FailOnSeverity: "high", NewFindingsOnly: &no,
		Reason: "legacy service, migrating"}
	if _, err := r.svc.CreateGatePolicy(ctx, r.tenant, looser, admin); !errors.Is(err, errNeedsStepUp) {
		t.Fatalf("loosening repository policy without step-up: %v", err)
	}
	// Turning the organization policy to warn needs it too, and stores nothing.
	if _, err := r.svc.UpdateGatePolicy(ctx, r.tenant, org.ID, cirunapp.GatePolicyInput{Mode: cirun.ModeWarn}, admin); !errors.Is(err, errNeedsStepUp) {
		t.Fatalf("warn without step-up: %v", err)
	}
	if p, _ := r.svc.GetGatePolicy(ctx, r.tenant, org.ID); p.Mode != cirun.ModeEnforce {
		t.Fatalf("refused change was stored: %s", p.Mode)
	}
	// Disabling the organization policy falls back to the built-in default
	// (high, new findings only): loosening.
	off := false
	if _, err := r.svc.UpdateGatePolicy(ctx, r.tenant, org.ID, cirunapp.GatePolicyInput{Enabled: &off}, admin); !errors.Is(err, errNeedsStepUp) {
		t.Fatalf("disable without step-up: %v", err)
	}
	if alerts.count() != 0 {
		t.Fatal("refused changes were announced")
	}

	// With a recent sign-in the change is made, audited high and announced.
	r.svc.SetStepUpGate(recentAuth{})
	repoPol, err := r.svc.CreateGatePolicy(ctx, r.tenant, looser, admin)
	if err != nil {
		t.Fatal(err)
	}
	if r.auditCount(r.tenant, "ci_gate_policy.loosened", "fail_on_severity") != 1 {
		t.Fatal("loosening not audited")
	}
	var sev string
	if err := r.db.QueryRowContext(ctx, `SELECT severity FROM audit_logs WHERE tenant_id = $1 AND action = 'ci_gate_policy.loosened'`,
		r.tenant.String()).Scan(&sev); err != nil || sev != "high" {
		t.Fatalf("severity %q %v", sev, err)
	}
	if alerts.count() != 1 || alerts.got[0].Metadata["action"] != "policy_loosened" {
		t.Fatalf("alerts %+v", alerts.got)
	}

	// Deleting the looser repository policy tightens: no step-up needed.
	r.svc.SetStepUpGate(recentAuth{err: errNeedsStepUp})
	if err := r.svc.DeleteGatePolicy(ctx, r.tenant, repoPol.ID, admin); err != nil {
		t.Fatalf("tightening delete asked for step-up: %v", err)
	}
	// Deleting the strict organization policy loosens.
	if err := r.svc.DeleteGatePolicy(ctx, r.tenant, org.ID, admin); !errors.Is(err, errNeedsStepUp) {
		t.Fatalf("loosening delete without step-up: %v", err)
	}
	// No step-up gate wired: loosening fails closed.
	r.svc.SetStepUpGate(nil)
	if err := r.svc.DeleteGatePolicy(ctx, r.tenant, org.ID, admin); !errors.Is(err, cirunapp.ErrStepUpUnavailable) {
		t.Fatalf("no gate: %v", err)
	}
}
