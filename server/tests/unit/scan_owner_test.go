package unit

// Scan ownership (docs/architecture/scan-ownership.md): a scheduled scan
// without an active owner is paused once and the administrators are told
// once; an administrator takes ownership; nothing saves a new ownerless
// scheduled scan.

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/actscope"
	scanservice "github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	notificationdom "github.com/openctemio/openctem/api/pkg/domain/notification"
	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// SetOwner is the compare-and-swap of postgres.ScanRepository.
func (m *mockScanRepo) SetOwner(_ context.Context, tenantID, id shared.ID, prev *shared.ID, owner shared.ID) (bool, error) {
	s, ok := m.scans[id.String()]
	if !ok || s.TenantID != tenantID {
		return false, nil
	}
	if (s.CreatedBy == nil) != (prev == nil) || (prev != nil && *s.CreatedBy != *prev) {
		return false, nil
	}
	s.SetCreatedBy(owner)
	return true, nil
}

type fakeAdminDirectory struct{ ids []shared.ID }

func (f fakeAdminDirectory) ActiveAdminIDs(context.Context, shared.ID) ([]shared.ID, error) {
	return f.ids, nil
}

type recordingNotifier struct {
	sent []notificationdom.NotificationParams
}

func (r *recordingNotifier) Notify(_ context.Context, p notificationdom.NotificationParams) error {
	r.sent = append(r.sent, p)
	return nil
}

type actOnNothing struct{}

func (actOnNothing) Check(_ context.Context, in actscope.Input) (*actscope.Decision, error) {
	d := &actscope.Decision{RefusedTargets: map[string]string{}, RefusedAssets: map[shared.ID]bool{}}
	for _, t := range in.Targets {
		d.RefusedTargets[t] = actscope.ReasonNoScopeTarget
	}
	return d, nil
}

func scheduledScan(t *testing.T, deps *testScanServiceDeps, tenantID shared.ID, name string) *scan.Scan {
	t.Helper()
	s := createTestScanInRepo(deps, tenantID, name, scan.ScanTypeSingle)
	s.ScheduleType = scan.ScheduleDaily
	return s
}

// An ownerless scheduled scan is refused, paused and the two administrators
// are told once; the paused scan is not due again, and a second refusal of
// an already paused scan sends nothing.
func TestScanOwner_OwnerlessScheduledRunPausesAndNotifiesOnce(t *testing.T) {
	svc, deps := newTestScanService()
	tenantID := shared.NewID()
	deps.toolRepo.addTool("nuclei", true)
	s := scheduledScan(t, deps, tenantID, "Ownerless daily")
	n := &recordingNotifier{}
	svc.SetOwnerNotifications(fakeAdminDirectory{ids: []shared.ID{shared.NewID(), shared.NewID()}}, n)

	sched := scanservice.TriggerScanExecInput{
		TenantID: tenantID.String(), ScanID: s.ID.String(), TriggerType: scanworkflow.TriggerTypeSchedule,
	}
	if _, err := svc.TriggerScan(context.Background(), sched); !errors.Is(err, scanservice.ErrScanHasNoOwner) {
		t.Fatalf("err = %v, want ErrScanHasNoOwner", err)
	}
	// A second due run (a race with the pause) finds the scan paused.
	if _, err := svc.TriggerScan(context.Background(), sched); err == nil {
		t.Fatal("a paused ownerless scan ran")
	}
	if s.Status != scan.StatusPaused || s.NextRunAt != nil {
		t.Fatalf("scan status = %s next_run_at = %v, want paused with no next run", s.Status, s.NextRunAt)
	}
	if len(n.sent) != 2 {
		t.Fatalf("notifications = %d, want one per administrator, once", len(n.sent))
	}
	for _, p := range n.sent {
		if p.TenantID != tenantID || p.ResourceID == nil || *p.ResourceID != s.ID || p.AudienceID == nil {
			t.Fatalf("notice not addressed to this tenant's administrators about this scan: %+v", p)
		}
	}
}

// An inactive owner pauses and notifies too.
func TestScanOwner_InactiveOwnerNotifies(t *testing.T) {
	svc, deps := newTestScanService()
	tenantID := shared.NewID()
	deps.toolRepo.addTool("nuclei", true)
	s := scheduledScan(t, deps, tenantID, "Leaver daily")
	s.SetCreatedBy(shared.NewID())
	svc.SetOwnerActivity(fakeOwnerActivity{active: false})
	n := &recordingNotifier{}
	svc.SetOwnerNotifications(fakeAdminDirectory{ids: []shared.ID{shared.NewID()}}, n)

	_, err := svc.TriggerScan(context.Background(), scanservice.TriggerScanExecInput{
		TenantID: tenantID.String(), ScanID: s.ID.String(), TriggerType: scanworkflow.TriggerTypeSchedule,
	})
	if !errors.Is(err, scanservice.ErrScanOwnerInactive) || len(n.sent) != 1 {
		t.Fatalf("err = %v notices = %d, want ErrScanOwnerInactive and one notice", err, len(n.sent))
	}
}

// Resuming an ownerless scheduled scan is refused: it would only be paused
// again at its next due run. Taking ownership, then resuming, works.
func TestScanOwner_TakeOwnershipThenResume(t *testing.T) {
	svc, deps := newTestScanService()
	tenantID := shared.NewID()
	s := scheduledScan(t, deps, tenantID, "Ownerless")
	_ = s.Pause()
	admin := shared.NewID()

	if _, err := svc.ActivateScan(context.Background(), tenantID.String(), s.ID.String()); !errors.Is(err, scanservice.ErrScanHasNoOwner) {
		t.Fatalf("resume without an owner: err = %v, want ErrScanHasNoOwner", err)
	}
	if got := svc.OwnerState(context.Background(), s); got != scanservice.OwnerStateMissing {
		t.Fatalf("owner state = %s, want missing", got)
	}

	got, err := svc.TakeOwnership(context.Background(), scanservice.TakeOwnershipInput{
		TenantID: tenantID.String(), ScanID: s.ID.String(), ActorID: admin.String(),
	})
	if err != nil {
		t.Fatalf("take ownership: %v", err)
	}
	if got.CreatedBy == nil || *got.CreatedBy != admin {
		t.Fatalf("owner = %v, want the administrator", got.CreatedBy)
	}
	if got.Status != scan.StatusPaused {
		t.Fatalf("taking ownership must not resume the scan, status = %s", got.Status)
	}
	var audited bool
	for _, ev := range deps.auditSvc.events {
		if ev.Action == audit.ActionScanConfigOwnerTaken {
			audited = true
		}
	}
	if !audited {
		t.Fatal("taking ownership was not audited")
	}
	if _, err := svc.ActivateScan(context.Background(), tenantID.String(), s.ID.String()); err != nil {
		t.Fatalf("resume after taking ownership: %v", err)
	}
}

// Ownership is never taken from an active member, never across tenants, and
// never by someone whose act scope does not cover the scan's targets.
func TestScanOwner_TakeOwnershipRefusals(t *testing.T) {
	ctx := context.Background()
	t.Run("active owner keeps the scan", func(t *testing.T) {
		svc, deps := newTestScanService()
		tenantID := shared.NewID()
		s := scheduledScan(t, deps, tenantID, "Owned")
		owner := shared.NewID()
		s.SetCreatedBy(owner)
		svc.SetOwnerActivity(fakeOwnerActivity{active: true})
		_, err := svc.TakeOwnership(ctx, scanservice.TakeOwnershipInput{TenantID: tenantID.String(), ScanID: s.ID.String(), ActorID: shared.NewID().String()})
		if !errors.Is(err, scanservice.ErrScanOwnerActive) || *s.CreatedBy != owner {
			t.Fatalf("err = %v owner = %v, want ErrScanOwnerActive and the owner unchanged", err, s.CreatedBy)
		}
	})
	t.Run("inactive owner can be replaced", func(t *testing.T) {
		svc, deps := newTestScanService()
		tenantID := shared.NewID()
		s := scheduledScan(t, deps, tenantID, "Leaver")
		s.SetCreatedBy(shared.NewID())
		svc.SetOwnerActivity(fakeOwnerActivity{active: false})
		admin := shared.NewID()
		if _, err := svc.TakeOwnership(ctx, scanservice.TakeOwnershipInput{TenantID: tenantID.String(), ScanID: s.ID.String(), ActorID: admin.String()}); err != nil || *s.CreatedBy != admin {
			t.Fatalf("err = %v owner = %v, want the administrator", err, s.CreatedBy)
		}
	})
	t.Run("another tenant's scan is not found", func(t *testing.T) {
		svc, deps := newTestScanService()
		s := scheduledScan(t, deps, shared.NewID(), "Theirs")
		_, err := svc.TakeOwnership(ctx, scanservice.TakeOwnershipInput{TenantID: shared.NewID().String(), ScanID: s.ID.String(), ActorID: shared.NewID().String()})
		if !errors.Is(err, shared.ErrNotFound) || s.CreatedBy != nil {
			t.Fatalf("err = %v owner = %v, want not found and no owner", err, s.CreatedBy)
		}
	})
	t.Run("targets outside the caller's act scope", func(t *testing.T) {
		svc, deps := newTestScanService(scanservice.WithActScope(actOnNothing{}))
		tenantID := shared.NewID()
		s := scheduledScan(t, deps, tenantID, "Out of scope")
		s.SetTargets([]string{"10.0.0.5"})
		_, err := svc.TakeOwnership(ctx, scanservice.TakeOwnershipInput{TenantID: tenantID.String(), ScanID: s.ID.String(), ActorID: shared.NewID().String()})
		if err == nil || s.CreatedBy != nil {
			t.Fatalf("err = %v owner = %v, want a refusal and no owner", err, s.CreatedBy)
		}
	})
	t.Run("no actor", func(t *testing.T) {
		svc, deps := newTestScanService()
		tenantID := shared.NewID()
		s := scheduledScan(t, deps, tenantID, "Nobody")
		_, err := svc.TakeOwnership(ctx, scanservice.TakeOwnershipInput{TenantID: tenantID.String(), ScanID: s.ID.String()})
		if !errors.Is(err, scanservice.ErrScanActorRequired) {
			t.Fatalf("err = %v, want ErrScanActorRequired", err)
		}
	})
}

// A scheduled scan created without an owner (an API key that belongs to no
// user) is refused; a manual one is still saved.
func TestScanOwner_CreateScheduledWithoutOwnerRefused(t *testing.T) {
	svc, deps := newTestScanService()
	tenantID := shared.NewID()
	deps.toolRepo.addTool("nuclei", true)
	in := scanservice.CreateScanInput{
		TenantID: tenantID.String(), Name: "Keyed", Targets: []string{"app.example.com"},
		ScanType: string(scan.ScanTypeSingle), ScannerName: "nuclei", TargetsPerJob: 1,
		ScheduleType: string(scan.ScheduleCrontab), ScheduleCron: "0 2 * * *",
	}
	if _, err := svc.CreateScan(context.Background(), in); !errors.Is(err, scanservice.ErrScheduledScanNeedsOwner) {
		t.Fatalf("scheduled without owner: err = %v, want ErrScheduledScanNeedsOwner", err)
	}
	in.CreatedBy = shared.NewID().String()
	if sc, err := svc.CreateScan(context.Background(), in); err != nil || sc.CreatedBy == nil {
		t.Fatalf("scheduled with owner: err = %v", err)
	}
	in.CreatedBy, in.ScheduleType, in.Name = "", string(scan.ScheduleManual), "Keyed manual"
	if _, err := svc.CreateScan(context.Background(), in); err != nil {
		t.Fatalf("manual scan without owner must still save: %v", err)
	}
}
