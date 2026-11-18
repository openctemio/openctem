package integration

import (
	"context"
	"errors"
	"net/http"
	"testing"

	cirunapp "github.com/openctemio/openctem/server/internal/app/cirun"
	"github.com/openctemio/openctem/server/pkg/domain/cirun"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

func (r *ciRig) allProjectsTrust(tenant shared.ID, admitNew bool) *cirun.TrustConfig {
	r.t.Helper()
	r.svc.SetNewRepositoryStore(r.repo)
	c, err := r.svc.CreateTrustConfig(context.Background(), tenant, cirunapp.TrustConfigInput{
		Name: "every-project", Provider: "gitlab", Issuer: r.idp.url,
		Rules: cirun.Rules{AllRepositories: true, AdmitNewRepositories: admitNew},
	}, cirunapp.Actor{Email: "admin@acme.test"})
	if err != nil {
		r.t.Fatalf("create all-projects trust: %v", err)
	}
	if !c.Rules.RequireProtectedRef || !c.Rules.NotifyNewGroups {
		r.t.Fatalf("safe defaults not set: %+v", c.Rules)
	}
	return c
}

// protectedToken is a job on a protected branch (the all-projects default
// admits protected refs only).
func (r *ciRig) protectedToken(t *testing.T, aud, project, job string) string {
	return r.idp.token(t, aud, project, "main", "1234123412341234123412341234123412341234",
		map[string]any{"ref_protected": "true", "job_id": job})
}

func (r *ciRig) decide(tenant, cfg shared.ID, action string, items ...cirun.NewRepositoryItem) error {
	_, err := r.svc.DecideNewRepositories(context.Background(), tenant, cfg,
		cirun.NewRepositoryDecision{Action: action, Items: items}, cirunapp.Actor{Email: "admin@acme.test"})
	return err
}

func (r *ciRig) countAudit(tenant shared.ID, action string) int {
	var n int
	_ = r.db.QueryRowContext(context.Background(), `SELECT count(*) FROM audit_logs WHERE tenant_id = $1 AND action = $2`,
		tenant.String(), action).Scan(&n)
	return n
}

// A project seen for the first time waits for approval (refused with a
// clear code, listed by group); approving the project admits it; approving
// its group admits every project of the group with no further pending item;
// a blocked project or group is refused at once and unblocking makes it new
// again; each decision is audited; another tenant cannot decide.
func TestCIAllProjects_PendingApproveBlock(t *testing.T) {
	r := newCIRig(t)
	cfg := r.allProjectsTrust(r.tenant, false)

	code, out := r.exchange(r.tenant, r.protectedToken(t, cfg.Audience, "alice/tool", "1"))
	if code != http.StatusUnauthorized || out["code"] != "CI_TOKEN_REPOSITORY_PENDING_APPROVAL" {
		t.Fatalf("new project: %d %v", code, out)
	}
	// Unprotected refs are refused by the rules before anything is recorded.
	unprot := r.idp.token(t, cfg.Audience, "bob/x", "feature", "5555555555555555555555555555555555555555", map[string]any{"ref_protected": "false"})
	if code, _ := r.exchange(r.tenant, unprot); code != http.StatusUnauthorized {
		t.Fatalf("unprotected ref admitted: %d", code)
	}
	list, err := r.svc.ListNewRepositories(context.Background(), r.tenant, cfg.ID)
	if err != nil || len(list.Rows) != 1 || list.Rows[0].Name != "alice/tool" || list.Rows[0].Group != "alice" {
		t.Fatalf("pending: %+v %v", list, err)
	}

	if _, err := r.svc.ListNewRepositories(context.Background(), r.other, cfg.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant list: %v", err)
	}
	if err := r.decide(r.other, cfg.ID, cirun.DecisionApprove, cirun.NewRepositoryItem{Kind: cirun.NewRepoProject, Name: "alice/tool"}); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant decision: %v", err)
	}
	if err := r.decide(r.tenant, cfg.ID, cirun.DecisionApprove, cirun.NewRepositoryItem{Kind: cirun.NewRepoProject, Name: "alice/tool"}); err != nil {
		t.Fatal(err)
	}
	if code, out := r.exchange(r.tenant, r.protectedToken(t, cfg.Audience, "alice/tool", "2")); code != http.StatusCreated {
		t.Fatalf("approved project: %d %v", code, out)
	}

	// Two projects of a new group; approving the group approves both and
	// every later project of it.
	for i, p := range []string{"platform/api", "platform/web"} {
		if code, _ := r.exchange(r.tenant, r.protectedToken(t, cfg.Audience, p, "g"+string(rune('0'+i)))); code != http.StatusUnauthorized {
			t.Fatalf("%s admitted before approval", p)
		}
	}
	if err := r.decide(r.tenant, cfg.ID, cirun.DecisionApprove, cirun.NewRepositoryItem{Kind: cirun.NewRepoGroup, Name: "Platform"}); err != nil {
		t.Fatal(err)
	}
	list, _ = r.svc.ListNewRepositories(context.Background(), r.tenant, cfg.ID)
	if len(list.Rows) != 0 || !containsString(list.Config.Rules.Owners, "platform") {
		t.Fatalf("after group approval: %+v %v", list.Rows, list.Config.Rules.Owners)
	}
	if code, out := r.exchange(r.tenant, r.protectedToken(t, cfg.Audience, "platform/new-service", "g9")); code != http.StatusCreated {
		t.Fatalf("future project of an approved group: %d %v", code, out)
	}

	// Block a project of the approved group, then the whole of another group.
	if err := r.decide(r.tenant, cfg.ID, cirun.DecisionBlock, cirun.NewRepositoryItem{Kind: cirun.NewRepoProject, Name: "platform/api"}); err != nil {
		t.Fatal(err)
	}
	if code, out := r.exchange(r.tenant, r.protectedToken(t, cfg.Audience, "platform/api", "b1")); code != http.StatusUnauthorized ||
		out["code"] != "CI_TOKEN_REPOSITORY_BLOCKED" {
		t.Fatalf("blocked project: %d %v", code, out)
	}
	if err := r.decide(r.tenant, cfg.ID, cirun.DecisionBlock, cirun.NewRepositoryItem{Kind: cirun.NewRepoGroup, Name: "eve"}); err != nil {
		t.Fatal(err)
	}
	if code, out := r.exchange(r.tenant, r.protectedToken(t, cfg.Audience, "eve/anything", "b2")); out["code"] != "CI_TOKEN_REPOSITORY_BLOCKED" {
		t.Fatalf("blocked group: %d %v", code, out)
	}
	if err := r.decide(r.tenant, cfg.ID, cirun.DecisionUnblock, cirun.NewRepositoryItem{Kind: cirun.NewRepoGroup, Name: "eve"}); err != nil {
		t.Fatal(err)
	}
	if _, out := r.exchange(r.tenant, r.protectedToken(t, cfg.Audience, "eve/anything", "b3")); out["code"] != "CI_TOKEN_REPOSITORY_PENDING_APPROVAL" {
		t.Fatalf("unblocked group: %v", out)
	}
	if n := r.countAudit(r.tenant, "ci_trust_config.new_repositories_decided"); n != 5 {
		t.Fatalf("decision audit rows: %d, want 5", n)
	}
	if n := r.countAudit(r.tenant, "ci_run.token_refused"); n < 4 {
		t.Fatalf("refusal audit rows: %d", n)
	}

	// Decisions are refused on a configuration that names its groups.
	named := r.trust(r.tenant, cirun.Rules{Owners: []string{"acme"}})
	if err := r.decide(r.tenant, named.ID, cirun.DecisionApprove, cirun.NewRepositoryItem{Kind: cirun.NewRepoGroup, Name: "x"}); !errors.Is(err, cirunapp.ErrNotAllRepositories) {
		t.Fatalf("decision on a named trust: %v", err)
	}
	for _, bad := range []cirun.NewRepositoryItem{{Kind: cirun.NewRepoGroup, Name: "a/b"}, {Kind: cirun.NewRepoProject, Name: "a"},
		{Kind: "owner", Name: "a"}, {Kind: cirun.NewRepoGroup, Name: "*"}} {
		if err := r.decide(r.tenant, cfg.ID, cirun.DecisionApprove, bad); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("%+v: %v", bad, err)
		}
	}
}

// With "admit new repositories" a new project's runs are admitted and it is
// still listed for approval (scope only after approval).
func TestCIAllProjects_AdmitNewStillListed(t *testing.T) {
	r := newCIRig(t)
	cfg := r.allProjectsTrust(r.tenant, true)
	if code, out := r.exchange(r.tenant, r.protectedToken(t, cfg.Audience, "alice/tool", "1")); code != http.StatusCreated {
		t.Fatalf("admit new: %d %v", code, out)
	}
	list, err := r.svc.ListNewRepositories(context.Background(), r.tenant, cfg.ID)
	if err != nil || len(list.Rows) != 1 || list.Rows[0].State != cirun.NewRepoPending {
		t.Fatalf("listed: %+v %v", list, err)
	}
	if got := cirun.ScopePatterns(list.Config); len(got) != 0 {
		t.Fatalf("an unapproved project reached scope patterns: %v", got)
	}
}

func containsString(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}
