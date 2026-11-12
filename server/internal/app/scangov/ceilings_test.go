package scangov

import (
	"context"
	"errors"
	"testing"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/pkg/domain/scangov"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// recCeilings records tier-ceiling changes and whether save ran before or
// after the signer was told.
type recCeilings struct {
	calls  []bool
	refuse bool
	saved  []bool // saved before the call returned
}

func (r *recCeilings) CommitTierCeilings(_ context.Context, _ shared.ID, enforced bool, _ string, _ scangov.Mode, save func() error) error {
	r.calls = append(r.calls, enforced)
	if r.refuse {
		return errors.New("signer refused")
	}
	if err := save(); err != nil {
		return err
	}
	r.saved = append(r.saved, true)
	return nil
}

// A mode change that crosses Strict is recorded with the signer's ledger
// (ceilings off when leaving Strict, on when entering); a refusal leaves
// the mode as it was; Off <-> On tells the ledger nothing.
func TestSetMode_TierCeilingsFollowStrict(t *testing.T) {
	ctx := context.Background()
	r := newRig(t, scangov.ModeStrict, nil)
	r.st.s.Mode = scangov.ModeStrict
	rec := &recCeilings{}
	r.svc.SetTierCeilings(rec)
	actx := auditapp.AuditContext{ActorID: shared.NewID().String()}

	rec.refuse = true
	if _, err := r.svc.SetMode(ctx, r.tid, scangov.ModeOn, "lighter", actx); err == nil {
		t.Fatal("a refused ceilings change still changed the mode")
	}
	if r.st.s.Mode != scangov.ModeStrict || len(rec.calls) != 1 || rec.calls[0] {
		t.Fatalf("mode %s calls %v: want Strict kept after one refused off", r.st.s.Mode, rec.calls)
	}
	rec.refuse = false
	if _, err := r.svc.SetMode(ctx, r.tid, scangov.ModeOn, "lighter", actx); err != nil {
		t.Fatal(err)
	}
	if r.st.s.Mode != scangov.ModeOn || len(rec.saved) != 1 {
		t.Fatalf("mode %s saved %v", r.st.s.Mode, rec.saved)
	}

	r.modes.m = scangov.ModeOn
	if _, err := r.svc.SetMode(ctx, r.tid, scangov.ModeOff, "off", actx); err != nil {
		t.Fatal(err)
	}
	if len(rec.calls) != 2 {
		t.Fatalf("On -> Off told the ledger: %v", rec.calls)
	}

	r.modes.m = scangov.ModeOff
	if _, err := r.svc.SetMode(ctx, r.tid, scangov.ModeStrict, "audit", actx); err != nil {
		t.Fatal(err)
	}
	if len(rec.calls) != 3 || !rec.calls[2] || r.st.s.Mode != scangov.ModeStrict {
		t.Fatalf("Off -> Strict: calls %v mode %s", rec.calls, r.st.s.Mode)
	}

	// Under a platform policy of at least On, choosing On again changes nothing
	// in force, nothing is sent.
	r.modes.p = scangov.PolicyOn
	r.modes.m = scangov.ModeOn
	if _, err := r.svc.SetMode(ctx, r.tid, scangov.ModeOn, "same", actx); err != nil {
		t.Fatal(err)
	}
	if len(rec.calls) != 3 {
		t.Fatalf("an unchanged mode told the ledger: %v", rec.calls)
	}
}
