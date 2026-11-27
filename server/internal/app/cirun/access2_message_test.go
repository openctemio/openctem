package cirun

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/server/pkg/domain/asset"
	"github.com/openctemio/openctem/server/pkg/domain/cirun"
	notificationdom "github.com/openctemio/openctem/server/pkg/domain/notification"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/logger"
)

type a2Repo struct{ cirun.Repository }

func (a2Repo) SetGateBaseline(context.Context, *cirun.GateBaseline) error { return nil }
func (a2Repo) CreateOverride(context.Context, *cirun.GateOverride) error  { return nil }

type a2StepUp struct{}

func (a2StepUp) RequireRecentAuth(context.Context, string) error { return nil }

func a2Service(t *testing.T) (*Service, *captureAlerts, shared.ID, *asset.Asset) {
	t.Helper()
	tenant := shared.NewID()
	a, err := asset.NewAssetWithTenant(tenant, "example/repo", asset.AssetTypeRepository, asset.CriticalityMedium)
	if err != nil {
		t.Fatal(err)
	}
	al := &captureAlerts{}
	s := &Service{repo: a2Repo{}, assets: renameAssets{a: a}, alerts: al, stepUp: a2StepUp{}, now: time.Now}
	s.log = logger.NewNop()
	return s, al, tenant, a
}

func a2Msg(t *testing.T, al *captureAlerts) *notificationdom.Message {
	t.Helper()
	if len(al.got) != 1 {
		t.Fatalf("%d alerts, want 1", len(al.got))
	}
	if al.got[0].Message == nil {
		t.Fatal("alert has no message")
	}
	return al.got[0].Message
}

func TestSetGateBaseline_AlertMessage(t *testing.T) {
	s, al, tenant, repo := a2Service(t)
	if _, err := s.SetGateBaseline(context.Background(), tenant, repo.ID(), Actor{Email: "ann@example.com"}); err != nil {
		t.Fatal(err)
	}
	m := a2Msg(t, al)
	if m.Code != "ci.baseline_recorded" || m.Params["by"] != "ann@example.com" || m.Params["repository"] != "example/repo" || m.Params["count"] != 0 {
		t.Errorf("message = %+v", m)
	}
	// No e-mail: the actor is the nested "an administrator" message.
	s, al, tenant, repo = a2Service(t)
	if _, err := s.SetGateBaseline(context.Background(), tenant, repo.ID(), Actor{}); err != nil {
		t.Fatal(err)
	}
	by, _ := a2Msg(t, al).Params["by"].(*notificationdom.Message)
	if by == nil || by.Code != "ci.someone.administrator" {
		t.Errorf("by = %+v", a2Msg(t, al).Params["by"])
	}
}

func TestCreateOverride_AlertMessage(t *testing.T) {
	s, al, tenant, repo := a2Service(t)
	sha := strings.Repeat("ab", 20)
	o, err := s.CreateOverride(context.Background(), tenant, OverrideInput{RepositoryAssetID: repo.ID(), CommitSHA: sha,
		Reason: "release is blocked by a known false positive"}, Actor{Email: "ann@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	m := a2Msg(t, al)
	if m.Code != "ci.break_glass_created" || m.Params["by"] != "ann@example.com" || m.Params["commit"] != sha[:12] ||
		m.Params["repository"] != "example/repo" || m.Params["reason"] != o.Reason ||
		m.Params["expires_at"] != o.ExpiresAt.Format(time.RFC3339) {
		t.Errorf("message = %+v", m)
	}
}

func TestAnnounceLoosened_AlertMessage(t *testing.T) {
	s, al, tenant, _ := a2Service(t)
	p := &cirun.GatePolicy{ID: shared.NewID(), ScopeType: cirun.ScopeTenant}
	s.announceLoosened(context.Background(), tenant, Actor{Email: "ann@example.com"}, p, []string{"mode", "fail_on_kev"})
	m := a2Msg(t, al)
	if m.Code != "ci.policy_loosened" || m.Params["by"] != "ann@example.com" || m.Params["scope"] != cirun.ScopeTenant ||
		m.Params["what"] != "mode, fail_on_kev" {
		t.Errorf("message = %+v", m)
	}
}

func TestFirstRunBaseline_AlertMessage(t *testing.T) {
	s, al, tenant, repo := a2Service(t)
	run := &cirun.Run{TenantID: tenant, RepositoryAssetID: repo.ID(), Repository: "example/repo",
		IsDefaultBranch: true, CommitVerified: true, Provider: cirun.ProviderGitHub}
	if b, err := s.firstRunBaseline(context.Background(), run); err != nil || b == nil {
		t.Fatalf("baseline %v err %v", b, err)
	}
	m := a2Msg(t, al)
	if m.Code != "ci.baseline_established" || m.Params["repository"] != "example/repo" || m.Params["count"] != 0 {
		t.Errorf("message = %+v", m)
	}
}

func TestAuditVerdict_BreakGlassUsedMessage(t *testing.T) {
	s, al, tenant, repo := a2Service(t)
	sha := strings.Repeat("cd", 20)
	run := &cirun.Run{ID: shared.NewID(), TenantID: tenant, RepositoryAssetID: repo.ID(), Repository: "example/repo",
		CommitSHA: sha, Provider: cirun.ProviderGitHub}
	v := &Verdict{}
	v.Verdict = cirun.VerdictPass
	v.Summary.Blocking = 4
	v.Override = &cirun.GateOverrideView{ID: shared.NewID().String()}
	s.auditVerdict(context.Background(), run, EvaluateInput{}, v)
	m := a2Msg(t, al)
	if m.Code != "ci.break_glass_used" || m.Params["repository"] != "example/repo" || m.Params["commit"] != sha[:12] || m.Params["blocking"] != 4 {
		t.Errorf("message = %+v", m)
	}
}

func TestNoticeNewGroup_AlertMessage(t *testing.T) {
	s, al, tenant, _ := a2Service(t)
	cfg := &cirun.TrustConfig{ID: shared.NewID(), Name: "gitlab-all"}
	s.noticeNewGroup(context.Background(), tenant, cfg, "team-a", "team-a/app")
	m := a2Msg(t, al)
	if m.Code != "ci.new_group_asks" || m.Params["group"] != "team-a" || m.Params["project"] != "team-a/app" || m.Params["trust"] != "gitlab-all" {
		t.Errorf("message = %+v", m)
	}
	// After a held-back burst the first notice says how many.
	now := time.Now()
	for i := 0; i < newGroupNoticesPerHour+3; i++ {
		s.groupNotices.take(cfg.ID.String(), now)
	}
	s.now = func() time.Time { return now.Add(newGroupNoticeWindow + time.Minute) }
	al.got = nil
	s.noticeNewGroup(context.Background(), tenant, cfg, "team-b", "team-b/app")
	m = a2Msg(t, al)
	if m.Code != "ci.new_group_asks_more" || m.Params["held"] != 4 {
		t.Errorf("message = %+v", m)
	}
}

func TestRenamedRepository_MessageWithoutTrustNames(t *testing.T) {
	s, al, tenant := renameService(t, "github.com/acme/old-name", true)
	s.noteRenamedRepository(context.Background(), tenant, ghIssuer, renamedClaims("acme/new-name"), nil)
	if len(al.got) == 0 {
		t.Skip("no alert without a configuration")
	}
	if m := al.got[0].Message; m == nil || m.Code != "ci.repository_renamed_any" || m.Params["new"] != "github.com/acme/new-name" {
		t.Errorf("message = %+v", al.got[0].Message)
	}
}
