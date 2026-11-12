package scangov

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/scangov"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
)

type profiles struct {
	byTenant map[shared.ID]map[string]scangov.Requester
	asked    []shared.ID
	fail     bool
}

func (p *profiles) RequesterProfile(_ context.Context, tid shared.ID, uid string) (scangov.Requester, error) {
	p.asked = append(p.asked, tid)
	if p.fail {
		return scangov.Requester{}, errors.New("db down")
	}
	return p.byTenant[tid][uid], nil
}

type tzSettings string

func (z tzSettings) GetTenantSettings(context.Context, string) (*tenant.Settings, error) {
	return &tenant.Settings{General: tenant.GeneralSettings{Timezone: string(z)}}, nil
}

const (
	botTrusted = "b0000000-0000-4000-8000-000000000001"
	botOther   = "b0000000-0000-4000-8000-000000000002"
	person     = "c0000000-0000-4000-8000-000000000001"
)

func originRig(t *testing.T, cond scangov.Conditions) (*rig, *profiles) {
	t.Helper()
	r := newRig(t, scangov.ModeOn, dir{{UserID: admin, Role: scangov.RoleAdmin}})
	rules, err := scangov.Normalize([]scangov.Rule{{Name: "Automation needs approval", Enabled: true, Conditions: cond,
		Requirement: scangov.Requirement{Approvals: 1}}})
	if err != nil {
		t.Fatal(err)
	}
	r.st.s.Rules = rules
	p := &profiles{byTenant: map[shared.ID]map[string]scangov.Requester{r.tid: {
		botTrusted: {ServiceAccount: true},
		botOther:   {ServiceAccount: true},
		person:     {Roles: []string{"member"}},
	}}}
	r.svc.SetRequesters(p, tzSettings("Asia/Ho_Chi_Minh"))
	return r, p
}

func (r *rig) runAs(ctx context.Context, user string) error {
	def, facts, _ := r.scans.GovernanceSubjectOf(ctx, r.sc)
	return r.svc.CheckRun(ctx, r.sc, def, facts, user)
}

// The origin comes from the authentication (ctx), a service account's key
// is the service_account origin, and only listed service accounts are
// trusted.
func TestCheckRun_OriginConditions(t *testing.T) {
	r, _ := originRig(t, scangov.Conditions{Origins: []string{"api_key", "service_account"},
		TrustedServiceAccountIDs: []string{botTrusted}})
	keyCtx := scangov.WithOrigin(context.Background(), scangov.OriginAPIKey)
	uiCtx := scangov.WithOrigin(context.Background(), scangov.OriginUI)

	if err := r.runAs(uiCtx, person); err != nil {
		t.Fatalf("a session run is not caught by an api_key rule: %v", err)
	}
	if err := r.runAs(keyCtx, person); !errors.Is(err, scangov.ErrApprovalRequired) {
		t.Fatalf("a person key run: %v, want approval required", err)
	}
	if err := r.runAs(keyCtx, botTrusted); err != nil {
		t.Fatalf("a trusted service account: %v", err)
	}
	if err := r.runAs(keyCtx, botOther); !errors.Is(err, scangov.ErrApprovalRequired) {
		t.Fatalf("an untrusted service account: %v", err)
	}
	// A session can never be a trusted service account.
	if err := r.runAs(uiCtx, botTrusted); err != nil {
		t.Fatalf("ui is not a listed origin: %v", err)
	}
}

// A scheduled run (no recorded origin) is the system acting for the
// scan's creator; a run with neither is caught (fail closed).
func TestCheckRun_ScheduledRunsAndUnknownRequester(t *testing.T) {
	r, p := originRig(t, scangov.Conditions{Origins: []string{"system"}, RequesterRoles: []string{"member"}})
	creator, _ := shared.IDFromString(person)
	r.sc.CreatedBy = &creator
	if err := r.runAs(context.Background(), ""); !errors.Is(err, scangov.ErrApprovalRequired) {
		t.Fatalf("a scheduled run of a member's scan: %v, want approval required", err)
	}
	if len(p.asked) == 0 || p.asked[len(p.asked)-1] != r.tid {
		t.Fatalf("the requester lookup used tenant %v, want the scan's own", p.asked)
	}
	r.sc.CreatedBy = nil
	if err := r.runAs(context.Background(), ""); !errors.Is(err, scangov.ErrApprovalRequired) {
		t.Fatalf("unknown requester must be caught: %v", err)
	}
	// A lookup failure refuses the run.
	r.sc.CreatedBy = &creator
	p.fail = true
	if err := r.runAs(context.Background(), ""); err == nil || errors.Is(err, scangov.ErrApprovalRequired) {
		t.Fatalf("a failed requester lookup: %v, want the run refused with an error", err)
	}
}

// Another tenant's profile of the same user never applies: the lookup is
// keyed by the scan's tenant.
func TestCheckRun_RequesterIsTenantScoped(t *testing.T) {
	r, p := originRig(t, scangov.Conditions{RequesterRoles: []string{"member"}})
	other := shared.NewID()
	p.byTenant[other] = map[string]scangov.Requester{botTrusted: {Roles: []string{"member"}}}
	ui := scangov.WithOrigin(context.Background(), scangov.OriginUI)
	if err := r.runAs(ui, botTrusted); err != nil {
		t.Fatalf("a member elsewhere is not a member here: %v", err)
	}
	if err := r.runAs(ui, person); !errors.Is(err, scangov.ErrApprovalRequired) {
		t.Fatalf("a member here: %v", err)
	}
}

// Hours are read in the organization's timezone at the time of the run.
func TestCheckRun_BusinessHours(t *testing.T) {
	r, _ := originRig(t, scangov.Conditions{Hours: &scangov.Hours{Windows: []scangov.Window{
		{Days: []string{"mon", "tue", "wed", "thu", "fri"}, Start: "09:00", End: "18:00"}}}})
	ui := scangov.WithOrigin(context.Background(), scangov.OriginUI)
	r.svc.SetClock(func() time.Time { return time.Date(2026, 10, 12, 3, 0, 0, 0, time.UTC) }) // Mon 10:00 ICT
	if err := r.runAs(ui, person); err != nil {
		t.Fatalf("inside business hours: %v", err)
	}
	r.svc.SetClock(func() time.Time { return time.Date(2026, 10, 12, 14, 0, 0, 0, time.UTC) }) // Mon 21:00 ICT
	if err := r.runAs(ui, person); !errors.Is(err, scangov.ErrApprovalRequired) {
		t.Fatalf("outside business hours: %v", err)
	}
}
