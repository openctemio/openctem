package tenant_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/audit"
	notificationdom "github.com/openctemio/openctem/api/pkg/domain/notification"
	"github.com/openctemio/openctem/api/pkg/domain/scangov"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// adminLister answers the organization's owners and administrators; every
// other lifecycle method is unused here.
type adminLister struct {
	tenantdom.LifecycleRepository
	ids []shared.ID
}

func (a adminLister) ActiveAdminIDs(context.Context, shared.ID) ([]shared.ID, error) {
	return a.ids, nil
}

type recordingInApp struct {
	mu     sync.Mutex
	titles []string
	to     []string
}

func (r *recordingInApp) Notify(_ context.Context, p notificationdom.NotificationParams) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.titles = append(r.titles, p.Title)
	if p.AudienceID != nil {
		r.to = append(r.to, p.AudienceID.String())
	}
	return nil
}

func (r *recordingInApp) take() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := r.titles
	r.titles, r.to = nil, nil
	return out
}

// Scan approval governance against the real settings table: lowering the
// mode (strict to on, on to off) and loosening the rules tell every owner and
// administrator; raising the mode, adding a rule and editing nothing tell
// nobody. Requires DATABASE_URL.
func TestScanGovernanceLowering_NotifiesAdmins(t *testing.T) {
	f := newSettingsFixture(t)
	ctx := context.Background()
	owner, admin := shared.NewID(), shared.NewID()
	inApp := &recordingInApp{}
	f.svc.SetLifecycleRepository(adminLister{ids: []shared.ID{owner, admin}})
	f.svc.SetLifecycleNotifier(inApp)

	set := func(mutate func(*tenantdom.ScanGovernanceSettings)) []string {
		t.Helper()
		if _, err := f.svc.UpdateScanGovernanceSettings(ctx, f.tenantID, func(s *tenantdom.ScanGovernanceSettings) error {
			mutate(s)
			return nil
		}, audit.ActionScanGovernanceModeChanged, "test", noAudit()); err != nil {
			t.Fatalf("update scan governance: %v", err)
		}
		return inApp.take()
	}

	// Off to strict with the light preset: a tightening.
	if got := set(func(s *tenantdom.ScanGovernanceSettings) {
		s.Mode, s.Rules = scangov.ModeStrict, scangov.Preset(scangov.PresetLight)
	}); len(got) != 0 {
		t.Fatalf("raising the mode notified: %v", got)
	}
	// Adding a rule: a tightening.
	if got := set(func(s *tenantdom.ScanGovernanceSettings) {
		extra := s.Rules[0]
		extra.ID, extra.Name = shared.NewID().String(), "Extra"
		s.Rules = append(s.Rules, extra)
	}); len(got) != 0 {
		t.Fatalf("adding a rule notified: %v", got)
	}
	// Strict to on: both administrators told.
	if got := set(func(s *tenantdom.ScanGovernanceSettings) { s.Mode = scangov.ModeOn }); len(got) != 2 || got[0] != "Scan approval lowered" {
		t.Fatalf("strict to on: notices %v, want two \"Scan approval lowered\"", got)
	}
	// An enforcing rule set to monitor only: rules loosened.
	if got := set(func(s *tenantdom.ScanGovernanceSettings) { s.Rules[0].Monitor = true }); len(got) != 2 || got[0] != "Scan approval rules loosened" {
		t.Fatalf("rule to monitor: notices %v", got)
	}
	// An enforcing rule removed: rules loosened.
	if got := set(func(s *tenantdom.ScanGovernanceSettings) { s.Rules = s.Rules[:len(s.Rules)-1] }); len(got) != 2 {
		t.Fatalf("rule removed: notices %v", got)
	}
	// On to off: lowered.
	if got := set(func(s *tenantdom.ScanGovernanceSettings) { s.Mode = scangov.ModeOff }); len(got) != 2 || got[0] != "Scan approval lowered" {
		t.Fatalf("on to off: notices %v", got)
	}
}

// Lowering the false-positive or risk acceptance approval level (two people
// to one) schedules a pending level; the settings write reports it so the
// change is audited critical and the approvers are told. Raising does not.
// Requires DATABASE_URL.
func TestFindingApprovalLowering_Detected(t *testing.T) {
	f := newSettingsFixture(t)
	ctx := context.Background()
	now := time.Now()
	before, after, err := f.svc.UpdateFindingApprovalSettings(ctx, f.tenantID, func(s *tenantdom.FindingApprovalSettings) error {
		return s.SetAcceptApproval("off", now)
	}, noAudit())
	if err != nil {
		t.Fatal(err)
	}
	if !tenantdom.ApprovalLoweringScheduled(*before, *after) {
		t.Fatalf("two-person to one-person risk acceptance must be a scheduled lowering: %+v", after)
	}
	before, after, err = f.svc.UpdateFindingApprovalSettings(ctx, f.tenantID, func(s *tenantdom.FindingApprovalSettings) error {
		return s.SetAcceptApproval("all", now)
	}, noAudit())
	if err != nil {
		t.Fatal(err)
	}
	if tenantdom.ApprovalLoweringScheduled(*before, *after) {
		t.Fatal("raising back is not a lowering")
	}
	before, after, err = f.svc.UpdateFindingApprovalSettings(ctx, f.tenantID, func(s *tenantdom.FindingApprovalSettings) error {
		return s.SetFPApproval("high_and_above", now)
	}, noAudit())
	if err != nil || !tenantdom.ApprovalLoweringScheduled(*before, *after) {
		t.Fatalf("false-positive all to high_and_above must be a scheduled lowering: %v", err)
	}
}
