package retest_test

// RFC-039 Phase 2 against a migrated Postgres: a regression gets a fresh SLA
// deadline with the reason recorded (D2), a fix or regression is announced,
// and a fix_applied finding is verified by a proof-of-fix retest.

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	retestapp "github.com/openctemio/openctem/api/internal/app/retest"
	appsla "github.com/openctemio/openctem/api/internal/app/sla"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	retestdom "github.com/openctemio/openctem/api/pkg/domain/retest"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type recordingAnnouncer struct {
	mu      sync.Mutex
	changes []retestapp.Change
}

func (r *recordingAnnouncer) Announce(_ context.Context, c retestapp.Change) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.changes = append(r.changes, c)
}

func (r *recordingAnnouncer) kinds() []retestapp.ChangeKind {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]retestapp.ChangeKind, 0, len(r.changes))
	for _, c := range r.changes {
		out = append(out, c.Kind)
	}
	return out
}

func (fx *fixture) regressionSLA() *appsla.RegressionRestarter {
	return appsla.NewRegressionRestarter(appsla.NewService(postgres.NewSLAPolicyRepository(fx.pg), logger.NewNop()),
		postgres.NewFindingSLARestartRepository(fx.pg), logger.NewNop())
}

// setOverdueSLA gives the finding an SLA deadline that passed a month ago.
func (fx *fixture) setOverdueSLA(f shared.ID) time.Time {
	past := time.Now().Add(-30 * 24 * time.Hour).UTC().Truncate(time.Second)
	fx.exec(`UPDATE findings SET sla_deadline = $2, sla_status = 'overdue' WHERE id = $1`, f.String(), past)
	return past
}

func (fx *fixture) sla(f shared.ID) (time.Time, string) {
	fx.t.Helper()
	var d time.Time
	var st string
	if err := fx.db.QueryRow(`SELECT sla_deadline, sla_status FROM findings WHERE id = $1`, f.String()).Scan(&d, &st); err != nil {
		fx.t.Fatal(err)
	}
	return d, st
}

func (fx *fixture) slaRestartActivity(f shared.ID) map[string]any {
	fx.t.Helper()
	var raw []byte
	var actor string
	if err := fx.db.QueryRow(`SELECT changes, actor_name FROM finding_activities WHERE finding_id = $1 AND activity_type = 'sla_restarted'`,
		f.String()).Scan(&raw, &actor); err != nil {
		fx.t.Fatalf("sla_restarted activity: %v", err)
	}
	var c map[string]any
	_ = json.Unmarshal(raw, &c)
	c["_actor"] = actor
	return c
}

// D2: a scan that sees a resolved finding again reopens it (ingest), and the
// regression gets a fresh SLA deadline instead of the month-old one.
func TestPhase2DB_ScanRegressionGetsFreshSLA(t *testing.T) {
	fx := newFixture(t)
	f := fx.newFinding(fx.asset, "resolved", "tpl-scan-regress")
	past := fx.setOverdueSLA(f)

	reopened, err := postgres.NewFindingRepository(fx.pg).AutoReopenByFingerprintsBatch(context.Background(), fx.tenant, []string{f.String()})
	if err != nil || len(reopened) != 1 {
		t.Fatalf("reopen: %v %v", reopened, err)
	}
	ann := &recordingAnnouncer{}
	retestapp.NewScanRegressions(fx.regressionSLA(), ann, logger.NewNop()).
		HandleRegressions(context.Background(), fx.tenant, []vulnerability.ReopenedFinding{reopened[f.String()]}, "nuclei")

	deadline, status := fx.sla(f)
	if !deadline.After(time.Now()) || status != "on_track" {
		t.Fatalf("regression SLA = %s / %s, want a fresh future deadline, on_track (was %s)", deadline, status, past)
	}
	c := fx.slaRestartActivity(f)
	if c["reason"] != "regression: fresh SLA deadline from the reopen" || c["trigger"] != "scan" ||
		c["previous_sla_deadline"] != past.Format(time.RFC3339) || c["_actor"] != "system: scan" {
		t.Errorf("sla_restarted activity = %v", c)
	}
	if k := ann.kinds(); len(k) != 1 || k[0] != retestapp.ChangeRegression {
		t.Errorf("announcements = %v, want one regression", k)
	}
}

// A validated_fixed finding a scan reopens was never closed: no SLA restart,
// no regression announcement.
func TestPhase2DB_ScanReopenOfValidatedFixedIsNotARegression(t *testing.T) {
	fx := newFixture(t)
	f := fx.newFinding(fx.asset, "validated_fixed", "tpl-downgrade")
	past := fx.setOverdueSLA(f)
	ann := &recordingAnnouncer{}
	retestapp.NewScanRegressions(fx.regressionSLA(), ann, logger.NewNop()).HandleRegressions(context.Background(), fx.tenant,
		[]vulnerability.ReopenedFinding{{ID: f, PreviousStatus: vulnerability.FindingStatusValidatedFixed}}, "nuclei")
	if d, _ := fx.sla(f); !d.Equal(past) {
		t.Errorf("SLA restarted for a refuted downgrade: %s", d)
	}
	if len(ann.kinds()) != 0 {
		t.Errorf("a refuted downgrade was announced as a regression")
	}
}

// D2 through a retest: still present on a resolved finding reopens it with a
// fresh SLA, and the regression is announced.
func TestPhase2DB_RetestRegressionGetsFreshSLAAndIsAnnounced(t *testing.T) {
	fx := newFixture(t)
	svc := fx.service()
	ann := &recordingAnnouncer{}
	svc.SetRegressionSLA(fx.regressionSLA())
	svc.SetAnnouncer(ann)

	f := fx.newFinding(fx.asset, "resolved", "tpl-retest-regress")
	past := fx.setOverdueSLA(f)
	rt := fx.request(svc, f)
	fx.finish(rt.CheckCommandID, "detected", "")
	fx.finish(rt.ReachCommandID, "detected", "")
	svc.OnCommandFinished(context.Background(), fx.tenant, *rt.CheckCommandID)

	if status, _, _ := fx.findingState(f); status != "confirmed" {
		t.Fatalf("finding = %s, want confirmed (regression)", status)
	}
	if d, st := fx.sla(f); !d.After(time.Now()) || st != "on_track" {
		t.Fatalf("SLA after a retest regression = %s / %s (was %s)", d, st, past)
	}
	if c := fx.slaRestartActivity(f); c["trigger"] != "retest" {
		t.Errorf("sla_restarted trigger = %v", c["trigger"])
	}
	if k := ann.kinds(); len(k) != 1 || k[0] != retestapp.ChangeRegression {
		t.Errorf("announcements = %v, want one regression", k)
	}
}

// A clean retest that resolves a finding is announced as a fix; an unknown one
// is announced as nothing.
func TestPhase2DB_RetestFixIsAnnouncedUnknownIsNot(t *testing.T) {
	fx := newFixture(t)
	svc := fx.service()
	ann := &recordingAnnouncer{}
	svc.SetAnnouncer(ann)

	fixed := fx.newFinding(fx.asset, "confirmed", "tpl-fixed")
	rt := fx.request(svc, fixed)
	fx.finish(rt.CheckCommandID, "not_detected", "")
	fx.finish(rt.ReachCommandID, "detected", "")
	svc.OnCommandFinished(context.Background(), fx.tenant, *rt.ReachCommandID)

	unknown := fx.newFinding(fx.newAsset("api.example.com"), "confirmed", "tpl-unknown")
	rt2 := fx.request(svc, unknown)
	fx.finish(rt2.CheckCommandID, "not_detected", "")
	fx.finish(rt2.ReachCommandID, "not_detected", "connection refused")
	svc.OnCommandFinished(context.Background(), fx.tenant, *rt2.ReachCommandID)

	if k := ann.kinds(); len(k) != 1 || k[0] != retestapp.ChangeFixed {
		t.Fatalf("announcements = %v, want exactly one fix", k)
	}
}

type fallbackValidator struct{ calls int }

func (v *fallbackValidator) ValidateFinding(context.Context, shared.ID, shared.ID) (shared.ID, error) {
	v.calls++
	return shared.NewID(), nil
}

// Marking a nuclei finding fix_applied starts a proof-of-fix retest (its own
// template + a reachability probe), not a whole-asset scan; a clean result
// resolves it. A finding with no deterministic re-check falls back to the
// plain validation re-check.
func TestPhase2DB_ProofOfFixRetestsAFixAppliedFinding(t *testing.T) {
	fx := newFixture(t)
	svc := fx.service()
	fallback := &fallbackValidator{}
	pof := retestapp.NewProofOfFix(svc, fallback)

	f := fx.newFinding(fx.asset, "fix_applied", "tpl-pof")
	id, err := pof.ValidateFinding(context.Background(), fx.tenant, f)
	if err != nil {
		t.Fatalf("proof of fix: %v", err)
	}
	rt := fx.retest(id)
	if rt.Trigger != retestdom.TriggerProofOfFix || rt.RequestedBy != nil {
		t.Fatalf("retest = %+v, want a system proof_of_fix retest", rt)
	}
	fx.finish(rt.CheckCommandID, "not_detected", "")
	fx.finish(rt.ReachCommandID, "detected", "")
	svc.OnCommandFinished(context.Background(), fx.tenant, *rt.CheckCommandID)
	if status, method, by := fx.findingState(f); status != "resolved" || method != "retest_verified" || by != "" {
		t.Fatalf("finding = %s/%s/%q, want resolved by the system", status, method, by)
	}
	if fallback.calls != 0 {
		t.Errorf("a retestable finding also went to the fallback")
	}

	trivy := fx.newFinding(fx.asset, "fix_applied", "CVE-2024-0001")
	fx.exec(`UPDATE findings SET tool_name = 'trivy' WHERE id = $1`, trivy.String())
	if _, err := pof.ValidateFinding(context.Background(), fx.tenant, trivy); err != nil {
		t.Fatal(err)
	}
	if fallback.calls != 1 {
		t.Errorf("a finding without a deterministic re-check did not fall back (calls=%d)", fallback.calls)
	}
}
