package unit

// Scope entry tier ceilings follow the scan approval mode (RFC-073 §6, §7):
// in Off and On an entry names targets for every tier, in Strict its
// max_tier is a ceiling. The job signer's ledger follows the same state:
// widenings carry it, mode changes that cross Strict record it (widening
// before save, narrowing after), and a refusal leaves the mode unchanged.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/scanpolicy"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/scangov"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/jobsign"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func ceilingsOf(t *testing.T, ch jobsign.LedgerChange) *bool {
	t.Helper()
	for _, op := range ch.Ops {
		if op.Op == jobsign.OpSetTierCeilings {
			return op.TierCeilings
		}
	}
	return nil
}

func TestTierCeilings_EnforcedOnlyInStrict(t *testing.T) {
	for m, want := range map[scangov.Mode]bool{scangov.ModeOff: false, scangov.ModeOn: false, scangov.ModeStrict: true} {
		if got := scangov.TierCeilingsEnforced(m); got != want {
			t.Fatalf("%s: enforced %v, want %v", m, got, want)
		}
	}
	if changed, _ := scangov.CeilingsChange(scangov.ModeOff, scangov.ModeOn); changed {
		t.Fatal("Off -> On changes no ceiling")
	}
	if changed, enforced := scangov.CeilingsChange(scangov.ModeOn, scangov.ModeStrict); !changed || !enforced {
		t.Fatal("On -> Strict turns the ceilings on")
	}
}

// Every widening carries the tenant's ceilings as the database has them;
// the snapshot says the same.
func TestTierCeilings_WideningsAndSnapshotCarryTheMode(t *testing.T) {
	for _, c := range []struct {
		mode    scangov.Mode
		enforce bool
	}{{scangov.ModeOff, false}, {scangov.ModeOn, false}, {scangov.ModeStrict, true}} {
		svc, _, _ := entryService(t, 3, tenant.ScopeSettings{})
		svc.SetGovernance(fixedMode{c.mode})
		led := &fakeLedger{}
		svc.SetLedger(led)
		tid := shared.NewID()
		if _, err := create(svc, tid, approverA, "*.ceilings.example", nil); err != nil {
			t.Fatal(err)
		}
		var widen *jobsign.LedgerChange
		for i := range led.changes {
			if len(led.changes[i].Ops) > 0 && led.changes[i].Ops[0].Op == jobsign.OpPutEntry {
				widen = &led.changes[i]
			}
		}
		if widen == nil {
			if c.mode == scangov.ModeStrict {
				continue // pending approval: nothing in effect yet
			}
			t.Fatalf("%s: no widening sent", c.mode)
		}
		got := ceilingsOf(t, *widen)
		if got == nil || *got != c.enforce {
			t.Fatalf("%s: widening carried ceilings %v, want %v", c.mode, got, c.enforce)
		}
		snap, err := svc.LedgerSnapshot(context.Background(), tid.String())
		if err != nil || snap.TierCeilingsOff == c.enforce {
			t.Fatalf("%s: snapshot ceilings off %v (%v)", c.mode, snap.TierCeilingsOff, err)
		}
	}
	// No governance wired: enforced (fail closed).
	svc, _, _ := entryService(t, 3, tenant.ScopeSettings{})
	if snap, _ := svc.LedgerSnapshot(context.Background(), shared.NewID().String()); snap.TierCeilingsOff {
		t.Fatal("without governance the ceilings must be enforced")
	}
}

// Turning the ceilings off goes to the signer before save, and a refusal
// or an unreachable signer saves nothing; turning them on saves first even
// when the signer is down.
func TestTierCeilings_CommitOrder(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := entryService(t, 3, tenant.ScopeSettings{})
	led := &fakeLedger{}
	svc.SetLedger(led)
	tid := shared.NewID()
	saved := 0
	save := func() error { saved++; return nil }

	led.refuse = true
	if err := svc.CommitTierCeilings(ctx, tid, false, "", scangov.ModeOn, save); err == nil || saved != 0 {
		t.Fatalf("refused widening: err %v saved %d", err, saved)
	}
	led.refuse, led.down = false, true
	if err := svc.CommitTierCeilings(ctx, tid, false, "", scangov.ModeOn, save); err == nil || saved != 0 {
		t.Fatalf("signer down: err %v saved %d", err, saved)
	}
	if err := svc.CommitTierCeilings(ctx, tid, true, "", scangov.ModeStrict, save); err != nil || saved != 1 {
		t.Fatalf("narrowing with the signer down must still save: err %v saved %d", err, saved)
	}
	led.down = false
	if err := svc.CommitTierCeilings(ctx, tid, false, "", scangov.ModeOff, save); err != nil || saved != 2 {
		t.Fatalf("accepted widening: err %v saved %d", err, saved)
	}
	last := led.changes[len(led.changes)-1]
	if last.TenantID != tid.String() || last.PlatformPolicy != "scan_approval:off" || *ceilingsOf(t, last) {
		t.Fatalf("change %+v", last)
	}
}

type ceilingCall struct {
	tenant   shared.ID
	enforced bool
	saved    bool // whether save had run when the signer was told
}

type recordedCeilings struct {
	calls  []ceilingCall
	refuse map[shared.ID]bool
	saved  *bool
}

func (r *recordedCeilings) CommitTierCeilings(_ context.Context, id shared.ID, enforced bool, _ string, _ scangov.Mode, save func() error) error {
	if !enforced && r.refuse[id] {
		r.calls = append(r.calls, ceilingCall{id, enforced, *r.saved})
		return errors.New("refused")
	}
	if !enforced {
		r.calls = append(r.calls, ceilingCall{id, enforced, *r.saved})
		return save()
	}
	if err := save(); err != nil {
		return err
	}
	r.calls = append(r.calls, ceilingCall{id, enforced, *r.saved})
	return nil
}

type savingPolicyRepo struct {
	*memPolicyRepo
	saved *bool
}

func (r savingPolicyRepo) SetOverride(ctx context.Context, id shared.ID, p *scangov.PlatformPolicy) error {
	*r.saved = true
	return r.memPolicyRepo.SetOverride(ctx, id, p)
}

// The platform override: leaving Strict is recorded before the override
// is saved (a refusal keeps Strict); only the organization concerned is
// told.
func TestTierCeilings_PlatformOverride(t *testing.T) {
	ctx := context.Background()
	saved := false
	repo := savingPolicyRepo{&memPolicyRepo{override: map[shared.ID]*scangov.PlatformPolicy{}}, &saved}
	svc := scanpolicy.NewService(repo, &adminAuditLog{}, nil, nil, &tenantNotes{}, logger.NewNop())
	org, other := shared.NewID(), shared.NewID()
	svc.SetSettings(govSettings{org.String(): {Mode: scangov.ModeOn}, other.String(): {Mode: scangov.ModeOn}})
	rec := &recordedCeilings{refuse: map[shared.ID]bool{}, saved: &saved}
	svc.SetTierCeilings(rec)
	actor, _ := admin.NewAdminUser("root@platform.test", "Root", admin.AdminRoleSuperAdmin, nil)
	ch := scanpolicy.Change{Actor: actor, Reason: "audit"}

	strict := scangov.PolicyStrict
	if err := svc.UpdateOverride(ctx, org, &strict, ch); err != nil {
		t.Fatal(err)
	}
	if len(rec.calls) != 1 || rec.calls[0] != (ceilingCall{org, true, true}) {
		t.Fatalf("entering Strict: %+v, want ceilings on after save, for org only", rec.calls)
	}

	saved = false
	rec.refuse[org] = true
	if err := svc.UpdateOverride(ctx, org, nil, ch); err == nil || saved {
		t.Fatalf("refused: err %v saved %v", err, saved)
	}
	if m, _, _, _ := svc.EffectiveMode(ctx, org); m != scangov.ModeStrict {
		t.Fatalf("a refused change left %s, want Strict", m)
	}
	rec.refuse[org] = false
	if err := svc.UpdateOverride(ctx, org, nil, ch); err != nil {
		t.Fatal(err)
	}
	last := rec.calls[len(rec.calls)-1]
	if last != (ceilingCall{org, false, false}) {
		t.Fatalf("leaving Strict: %+v, want ceilings off before save", last)
	}
	for _, c := range rec.calls {
		if c.tenant == other {
			t.Fatal("another organization's ceilings changed")
		}
	}
}

type followers struct {
	*memPolicyRepo
	ids   []shared.ID
	saved *bool
}

func (f followers) ListFollowingDefault(context.Context) ([]shared.ID, error) { return f.ids, nil }

func (f followers) SetDefault(ctx context.Context, p scangov.PlatformPolicy, v int, by shared.ID, at time.Time) (int, error) {
	*f.saved = true
	return f.memPolicyRepo.SetDefault(ctx, p, v, by, at)
}

// The platform default: every following organization whose mode crosses
// Strict is told, wideners before save; one refusal fails the change and
// narrows back the ones already accepted; an organization with its own
// override is not touched.
func TestTierCeilings_PlatformDefault(t *testing.T) {
	ctx := context.Background()
	saved := false
	a, b, c, pinned := shared.NewID(), shared.NewID(), shared.NewID(), shared.NewID()
	strict := scangov.PolicyStrict
	base := &memPolicyRepo{def: &strict, version: 1, override: map[shared.ID]*scangov.PlatformPolicy{pinned: &strict}}
	repo := followers{base, []shared.ID{a, b, c}, &saved}
	svc := scanpolicy.NewService(repo, &adminAuditLog{}, nil, nil, &tenantNotes{}, logger.NewNop())
	svc.SetSettings(govSettings{a.String(): {Mode: scangov.ModeOff}, b.String(): {Mode: scangov.ModeStrict},
		c.String(): {Mode: scangov.ModeOn}})
	rec := &recordedCeilings{refuse: map[shared.ID]bool{c: true}, saved: &saved}
	svc.SetTierCeilings(rec)
	actor, _ := admin.NewAdminUser("root@platform.test", "Root", admin.AdminRoleSuperAdmin, nil)
	ch := scanpolicy.Change{Actor: actor, Reason: "relax default"}

	// Strict -> tenant_controlled: a (chose Off) and c (chose On) leave
	// Strict, b (chose Strict) stays, pinned has its own override.
	if _, err := svc.UpdateDefault(ctx, scangov.PolicyTenantControlled, 1, ch); err == nil || saved {
		t.Fatalf("a refused follower must fail the change: err %v saved %v", err, saved)
	}
	want := []ceilingCall{{a, false, false}, {c, false, false}, {a, true, false}}
	if len(rec.calls) != len(want) {
		t.Fatalf("calls %+v, want %+v (a narrowed back after c was refused)", rec.calls, want)
	}
	for i := range want {
		if rec.calls[i] != want[i] {
			t.Fatalf("calls %+v, want %+v", rec.calls, want)
		}
	}
	rec.calls, rec.refuse = nil, map[shared.ID]bool{}
	if _, err := svc.UpdateDefault(ctx, scangov.PolicyTenantControlled, 1, ch); err != nil {
		t.Fatal(err)
	}
	if len(rec.calls) != 2 || rec.calls[0] != (ceilingCall{a, false, false}) || rec.calls[1] != (ceilingCall{c, false, false}) {
		t.Fatalf("calls %+v, want a and c off before save, nothing for b or pinned", rec.calls)
	}
	// Back to Strict: both told after save.
	rec.calls = nil
	saved = false
	if _, err := svc.UpdateDefault(ctx, scangov.PolicyStrict, 2, ch); err != nil {
		t.Fatal(err)
	}
	if len(rec.calls) != 2 || !rec.calls[0].enforced || !rec.calls[0].saved || !rec.calls[1].saved {
		t.Fatalf("calls %+v, want a and c on after save", rec.calls)
	}
}
