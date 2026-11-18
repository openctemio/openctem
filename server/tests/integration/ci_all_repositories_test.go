package integration

import (
	"context"
	"errors"
	"fmt"
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

// sighting is a protected-branch job of project with the given verified
// project and namespace ids.
func (r *ciRig) sighting(t *testing.T, aud, project, projectID, namespaceID, job string) string {
	return r.idp.token(t, aud, project, "main", "1234123412341234123412341234123412341234",
		map[string]any{"ref_protected": "true", "job_id": job, "project_id": projectID, "namespace_id": namespaceID})
}

// Review finding: an approval on an all-projects configuration changes its
// owners or repositories, which used to drop every owner pin. A group renamed
// on the instance and re-registered by someone else (same name, new
// namespace id) was then admitted after any routine approval. The pin of a
// name still listed survives an approval of another project.
func TestCIAllProjects_ApprovalKeepsOwnerPins(t *testing.T) {
	r := newCIRig(t)
	ctx := context.Background()
	cfg := r.allProjectsTrust(r.tenant, false)
	if code, _ := r.exchange(r.tenant, r.sighting(t, cfg.Audience, "acme/api", "7", "42", "1")); code != http.StatusUnauthorized {
		t.Fatalf("new project admitted: %d", code)
	}
	if err := r.decide(r.tenant, cfg.ID, cirun.DecisionApprove, cirun.NewRepositoryItem{Kind: cirun.NewRepoGroup, Name: "acme"}); err != nil {
		t.Fatal(err)
	}
	if code, out := r.exchange(r.tenant, r.sighting(t, cfg.Audience, "acme/api", "7", "42", "2")); code != http.StatusCreated {
		t.Fatalf("approved group: %d %v", code, out)
	}
	// Routine approval of an unrelated project.
	if code, _ := r.exchange(r.tenant, r.sighting(t, cfg.Audience, "x/y", "8", "50", "3")); code != http.StatusUnauthorized {
		t.Fatalf("new project admitted: %d", code)
	}
	if err := r.decide(r.tenant, cfg.ID, cirun.DecisionApprove, cirun.NewRepositoryItem{Kind: cirun.NewRepoProject, Name: "x/y"}); err != nil {
		t.Fatal(err)
	}
	pins, err := r.svc.OwnerPins(ctx, r.tenant, cfg.ID)
	if err != nil || !hasPin(pins, "acme", "42") {
		t.Fatalf("pin of acme after an unrelated approval: %+v %v", pins, err)
	}
	// acme renamed on the instance; someone registers a new acme (id 99).
	code, out := r.exchange(r.tenant, r.sighting(t, cfg.Audience, "acme/new-tool", "9", "99", "4"))
	if code != http.StatusUnauthorized || out["code"] != "CI_TOKEN_OWNER_ID_MISMATCH" {
		t.Fatalf("re-registered group after an approval: %d %v", code, out)
	}
}

func hasPin(pins []cirun.OwnerPin, name, id string) bool {
	for _, p := range pins {
		if p.OwnerName == name && p.OwnerID == id {
			return true
		}
	}
	return false
}

// Review finding: the administrator approves what was seen. The pending row
// keeps the verified project and namespace ids of the sighting, and the
// approval binds to them: a project that takes the path over between the
// sighting and the first admitted run is refused.
func TestCIAllProjects_ApprovalBindsSeenIDs(t *testing.T) {
	r := newCIRig(t)
	ctx := context.Background()
	cfg := r.allProjectsTrust(r.tenant, false)
	if code, _ := r.exchange(r.tenant, r.sighting(t, cfg.Audience, "alice/tool", "70", "500", "1")); code != http.StatusUnauthorized {
		t.Fatalf("new project admitted: %d", code)
	}
	list, err := r.svc.ListNewRepositories(ctx, r.tenant, cfg.ID)
	if err != nil || len(list.Rows) != 1 || list.Rows[0].ProjectID != "70" || list.Rows[0].NamespaceID != "500" {
		t.Fatalf("pending row ids: %+v %v", list.Rows, err)
	}
	if err := r.decide(r.tenant, cfg.ID, cirun.DecisionApprove, cirun.NewRepositoryItem{Kind: cirun.NewRepoProject, Name: "alice/tool"}); err != nil {
		t.Fatal(err)
	}
	if pins, _ := r.svc.OwnerPins(ctx, r.tenant, cfg.ID); !hasPin(pins, "alice", "500") {
		t.Fatalf("approval did not pin the namespace seen: %+v", pins)
	}
	// The path changed hands: another namespace, then another project id.
	if code, out := r.exchange(r.tenant, r.sighting(t, cfg.Audience, "alice/tool", "70", "501", "2")); code != http.StatusUnauthorized ||
		out["code"] != "CI_TOKEN_OWNER_ID_MISMATCH" {
		t.Fatalf("other namespace after approval: %d %v", code, out)
	}
	if code, out := r.exchange(r.tenant, r.sighting(t, cfg.Audience, "alice/tool", "71", "500", "3")); code != http.StatusUnauthorized ||
		out["code"] != "CI_TOKEN_REPOSITORY_BINDING" {
		t.Fatalf("other project id after approval: %d %v", code, out)
	}
	if code, out := r.exchange(r.tenant, r.sighting(t, cfg.Audience, "alice/tool", "70", "500", "4")); code != http.StatusCreated {
		t.Fatalf("approved project with the ids seen: %d %v", code, out)
	}
	// An approved row is not listed as pending.
	if list, _ := r.svc.ListNewRepositories(ctx, r.tenant, cfg.ID); len(list.Rows) != 0 {
		t.Fatalf("approved row listed: %+v", list.Rows)
	}
}

// Review finding: one instance user filling the pending list. A group keeps
// at most cirun.MaxPendingPerGroup pending projects; past it a project is
// refused without being listed and the list names the full group, while
// projects of other groups are still recorded.
func TestCIAllProjects_PendingCapPerGroup(t *testing.T) {
	r := newCIRig(t)
	ctx := context.Background()
	cfg := r.allProjectsTrust(r.tenant, false)
	for i := 0; i <= cirun.MaxPendingPerGroup; i++ {
		p := fmt.Sprintf("spam/p%02d", i)
		if code, _ := r.exchange(r.tenant, r.sighting(t, cfg.Audience, p, fmt.Sprint(1000+i), "66", "s"+fmt.Sprint(i))); code != http.StatusUnauthorized {
			t.Fatalf("%s admitted", p)
		}
	}
	if code, _ := r.exchange(r.tenant, r.sighting(t, cfg.Audience, "team/app", "2000", "77", "t1")); code != http.StatusUnauthorized {
		t.Fatal("team/app admitted")
	}
	list, err := r.svc.ListNewRepositories(ctx, r.tenant, cfg.ID)
	if err != nil {
		t.Fatal(err)
	}
	spam, team := 0, 0
	for _, row := range list.Rows {
		switch row.Group {
		case "spam":
			spam++
		case "team":
			team++
		}
	}
	if spam != cirun.MaxPendingPerGroup || team != 1 {
		t.Fatalf("pending spam=%d team=%d", spam, team)
	}
	if list.ListFull || len(list.FullGroups) != 1 || list.FullGroups[0] != "spam" {
		t.Fatalf("full flags: list_full=%v groups=%v", list.ListFull, list.FullGroups)
	}
}

// Review finding: the trust preview ran the rules only and reported an
// all-projects configuration as admitting any project, while the exchange
// answers "pending approval". The preview now reports the same step.
func TestCIAllProjects_PreviewShowsPendingApproval(t *testing.T) {
	r := newCIRig(t)
	ctx := context.Background()
	tok := r.sighting(t, cirun.DefaultAudience(r.tenant), "alice/tool", "70", "500", "p1")
	draft := cirunapp.TrustConfigInput{Name: "draft", Provider: "gitlab", Issuer: r.idp.url,
		Rules: cirun.Rules{AllRepositories: true, RequireProtectedRef: true}}
	preview := func() *cirunapp.PreviewResult {
		t.Helper()
		out, err := r.svc.PreviewTrust(ctx, r.tenant, cirunapp.PreviewInput{Config: draft, IDToken: tok})
		if err != nil || !out.Verified {
			t.Fatalf("preview: %+v %v", out, err)
		}
		return out
	}
	if out := preview(); out.Admitted || out.Refusal == nil || out.Refusal.Code != cirun.RefuseRepositoryPending {
		t.Fatalf("new project previewed as %+v %+v", out.Admitted, out.Refusal)
	}
	draft.Rules.AdmitNewRepositories = true
	if out := preview(); !out.Admitted || !out.PendingApproval {
		t.Fatalf("admit-new preview: admitted=%v pending=%v %+v", out.Admitted, out.PendingApproval, out.Refusal)
	}
	draft.Rules.AdmitNewRepositories, draft.Rules.Owners = false, []string{"alice"}
	if out := preview(); !out.Admitted || out.PendingApproval {
		t.Fatalf("approved group preview: admitted=%v pending=%v %+v", out.Admitted, out.PendingApproval, out.Refusal)
	}
}
