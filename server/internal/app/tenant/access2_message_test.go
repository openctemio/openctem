package tenant

import (
	"context"
	"testing"
	"time"

	auditapp "github.com/openctemio/openctem/server/internal/app/audit"
	notificationdom "github.com/openctemio/openctem/server/pkg/domain/notification"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/server/pkg/domain/tenant"
	"github.com/openctemio/openctem/server/pkg/logger"
)

type a2Lifecycle struct {
	fixedAdmins
}

func (a2Lifecycle) Disable(context.Context, *tenantdom.Membership) (*tenantdom.DisableResult, error) {
	return &tenantdom.DisableResult{}, nil
}

type a2Repo struct {
	tenantdom.Repository
	members []*tenantdom.Membership
}

func (r a2Repo) ListExternalHomed(context.Context, tenantdom.HomedFilter) ([]*tenantdom.Membership, error) {
	return r.members, nil
}

func (r a2Repo) ListActiveExternalFromHome(context.Context, shared.ID, shared.ID) ([]*tenantdom.Membership, error) {
	return r.members, nil
}

func (r a2Repo) DeletePendingInvitationsByUserID(context.Context, shared.ID, shared.ID) (int64, error) {
	return 0, nil
}

func a2External(host shared.ID, expires *time.Time) *tenantdom.Membership {
	home := shared.NewID()
	return tenantdom.ReconstituteMembership(shared.NewID(), shared.NewID(), host, tenantdom.RoleMember, nil, time.Now()).
		WithAccessState(tenantdom.MemberKindExternal, &home, "example.org", expires, "", "")
}

func a2Service(rec *recordingNotifier, repo tenantdom.Repository) *TenantService {
	return &TenantService{
		repo:              repo,
		lifecycle:         a2Lifecycle{fixedAdmins{ids: []shared.ID{shared.NewID()}}},
		lifecycleNotifier: rec,
		userInfoProvider:  fixedName{},
		logger:            logger.NewNop(),
	}
}

func a2One(t *testing.T, rec *recordingNotifier) *notificationdom.Message {
	t.Helper()
	if len(rec.got) != 1 {
		t.Fatalf("%d notices, want 1", len(rec.got))
	}
	m := rec.got[0].params.Message
	if m == nil {
		t.Fatal("notice has no message")
	}
	return m
}

func TestExpireMembership_MessageCode(t *testing.T) {
	host := shared.NewID()
	past := time.Now().Add(-time.Hour)
	m := a2External(host, &past)
	rec := &recordingNotifier{}
	svc := a2Service(rec, a2Repo{})
	if err := svc.expireMembership(context.Background(), m, time.Now()); err != nil {
		t.Fatal(err)
	}
	if got := a2One(t, rec); got.Code != "member.access_expired" {
		t.Errorf("code = %q", got.Code)
	}
}

func TestHomeCascade_MessageCodes(t *testing.T) {
	host := shared.NewID()
	for _, tc := range []struct {
		code string
		run  func(*TenantService)
	}{
		{"trust.home_access_ended", func(s *TenantService) { s.homeAccessEnded(context.Background(), shared.NewID(), shared.NewID()) }},
		{"trust.home_domain_lapsed", func(s *TenantService) { s.HomeDomainLost(context.Background(), shared.NewID(), "example.org") }},
	} {
		rec := &recordingNotifier{}
		svc := a2Service(rec, a2Repo{members: []*tenantdom.Membership{a2External(host, nil)}})
		tc.run(svc)
		if got := a2One(t, rec); got.Code != tc.code {
			t.Errorf("code = %q, want %q", got.Code, tc.code)
		}
	}
}

func TestSuspendExternalMembersFromHome_MessageCount(t *testing.T) {
	host := shared.NewID()
	rec := &recordingNotifier{}
	svc := a2Service(rec, a2Repo{members: []*tenantdom.Membership{a2External(host, nil), a2External(host, nil)}})
	n, err := svc.SuspendExternalMembersFromHome(context.Background(), host, shared.NewID(), tenantdom.SuspendedReasonTrustRevoked)
	if err != nil || n != 2 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	m := a2One(t, rec)
	if m.Code != "trust.members_suspended" || m.Params["count"] != 2 {
		t.Errorf("message = %+v", m)
	}
}

func TestNotifyAdminsMsg_Public(t *testing.T) {
	rec := &recordingNotifier{}
	svc := a2Service(rec, nil)
	svc.NotifyAdminsMsg(context.Background(), shared.NewID(), notificationdom.Msg("org.test", "k", 1), "t", "b", "info")
	if m := a2One(t, rec); m.Code != "org.test" {
		t.Errorf("message = %+v", m)
	}
}

func TestPrivilegeIncrease_MessageCode(t *testing.T) {
	rec := &recordingNotifier{}
	svc := a2Service(rec, nil)
	svc.notifyPrivilegeIncrease(context.Background(), shared.NewID(), shared.NewID(), "x", notificationdom.Msg("member.privilege.role_raised", "from_role", roleMessage("viewer"), "to_role", roleMessage("admin")))
	m := a2One(t, rec)
	what, _ := m.Params["what"].(*notificationdom.Message)
	if m.Code != "member.privileges_gained" || m.Params["member"] != "Alice" || what == nil ||
		what.Code != "member.privilege.role_raised" || !isRole(what.Params["from_role"], "member.role.viewer") || !isRole(what.Params["to_role"], "member.role.admin") {
		t.Errorf("message = %+v", m)
	}
	// The public form takes free text: no code, English only.
	rec2 := &recordingNotifier{}
	a2Service(rec2, nil).NotifyPrivilegeIncrease(context.Background(), shared.NewID(), shared.NewID(), "free text")
	if len(rec2.got) != 1 || rec2.got[0].params.Message != nil {
		t.Errorf("public form should carry no message: %+v", rec2.got)
	}
}

func TestPausedMessage(t *testing.T) {
	ref := tenantdom.LifecycleRef{}
	for _, tc := range []struct {
		r    tenantdom.DisableResult
		code string
	}{
		{tenantdom.DisableResult{PausedScans: []tenantdom.LifecycleRef{ref}}, "member.paused.scans"},
		{tenantdom.DisableResult{PausedReports: []tenantdom.LifecycleRef{ref}, PausedWorkflow: []tenantdom.LifecycleRef{ref}}, "member.paused.reports_workflows"},
		{tenantdom.DisableResult{PausedScans: []tenantdom.LifecycleRef{ref, ref}, PausedReports: []tenantdom.LifecycleRef{ref}, PausedWorkflow: []tenantdom.LifecycleRef{ref}}, "member.paused.scans_reports_workflows"},
	} {
		m := pausedMessage(&tc.r)
		if m.Code != tc.code || m.Params["scans"] != len(tc.r.PausedScans) || m.Params["reports"] != len(tc.r.PausedReports) || m.Params["workflows"] != len(tc.r.PausedWorkflow) {
			t.Errorf("%s: message = %+v", tc.code, m)
		}
	}
}

func TestNotifyPolicyLoosenedCode_Message(t *testing.T) {
	rec := &recordingNotifier{}
	svc := a2Service(rec, nil)
	tid := shared.NewID().String()
	svc.notifyPolicyLoosenedCode(context.Background(), tid, auditapp.AuditContext{ActorID: shared.NewID().String()},
		"settings.pentest_loosened", "t", "w", "/x")
	if m := a2One(t, rec); m.Code != "settings.pentest_loosened" || m.Params["who"] != "Alice" {
		t.Errorf("message = %+v", m)
	}
	// No known actor: "who" is the nested "an administrator" message.
	rec = &recordingNotifier{}
	svc = a2Service(rec, nil)
	svc.userInfoProvider = nil
	svc.notifyPolicyLoosenedCode(context.Background(), tid, auditapp.AuditContext{}, "settings.easm_loosened", "t", "w", "/x")
	m := a2One(t, rec)
	who, _ := m.Params["who"].(*notificationdom.Message)
	if who == nil || who.Code != "settings.someone.administrator" {
		t.Errorf("who = %+v", m.Params["who"])
	}
	// The unconverted form stays English only.
	rec = &recordingNotifier{}
	a2Service(rec, nil).notifyPolicyLoosened(context.Background(), tid, auditapp.AuditContext{}, "t", "w", "/x")
	if len(rec.got) != 1 || rec.got[0].params.Message != nil {
		t.Errorf("uncoded form should carry no message")
	}
}

func TestNotifySecurityLoosened_MessageCode(t *testing.T) {
	ctx := context.Background()
	tid := shared.NewID().String()
	actx := auditapp.AuditContext{ActorID: shared.NewID().String()}
	for _, tc := range []struct {
		name          string
		before, after tenantdom.SecuritySettings
		code          string
		changes       []string
	}{
		{"sign-in", tenantdom.SecuritySettings{MFARequired: true, IPWhitelist: []string{"10.0.0.0/8"}}, tenantdom.SecuritySettings{},
			"settings.sign_in_loosened", []string{"settings.security.change.mfa_off", "settings.security.change.ip_emptied"}},
		{"sensor jobs", tenantdom.SecuritySettings{}, tenantdom.SecuritySettings{AllowSensorInteractsh: true},
			"settings.sensor_jobs_loosened", []string{"settings.security.change.interactsh"}},
	} {
		rec := &recordingNotifier{}
		a2Service(rec, nil).notifySecurityLoosened(ctx, tid, actx, tc.before, tc.after)
		if len(rec.got) == 0 {
			t.Fatalf("%s: no notice (severity below High?)", tc.name)
		}
		m := rec.got[0].params.Message
		if m == nil || m.Code != tc.code || m.Params["who"] != "Alice" {
			t.Fatalf("%s: message = %+v", tc.name, m)
		}
		what, _ := m.Params["what"].(*notificationdom.Message)
		if what == nil || what.Code != "settings.security.changes" {
			t.Fatalf("%s: what = %+v", tc.name, m.Params["what"])
		}
		lines, _ := what.Params["lines"].([]notificationdom.Message)
		if len(lines) != len(tc.changes) {
			t.Fatalf("%s: lines = %+v", tc.name, lines)
		}
		for i, c := range tc.changes {
			if lines[i].Code != c {
				t.Errorf("%s: line %d = %q, want %q", tc.name, i, lines[i].Code, c)
			}
		}
	}
}

func isRole(v any, code string) bool {
	m, _ := v.(*notificationdom.Message)
	return m != nil && m.Code == code
}

func TestRoleMessage(t *testing.T) {
	if roleMessage("owner").Code != "member.role.owner" || roleMessage("custom role!").Code != "member.role.other" {
		t.Error("role codes")
	}
}
