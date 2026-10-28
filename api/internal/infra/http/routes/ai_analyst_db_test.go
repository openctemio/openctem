package routes

// AI analysts on a real database (docs/architecture/ai-analysis.md): an
// analyst is a service account that acts like a person within its role, never
// beyond what its accountable owners hold, never as an approver, never across
// organizations, and it pauses when no owner is left or its attestation ran
// out.

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/accesscontrol"
	"github.com/openctemio/openctem/api/internal/app/aianalysis"
	"github.com/openctemio/openctem/api/internal/app/apikey"
	"github.com/openctemio/openctem/api/internal/app/datascope"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	aidom "github.com/openctemio/openctem/api/pkg/domain/aianalysis"
	"github.com/openctemio/openctem/api/pkg/domain/limits"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	roledom "github.com/openctemio/openctem/api/pkg/domain/role"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type aiRolePerms struct{ roles *postgres.RoleRepository }

func (s aiRolePerms) GetPermissionsWithFallback(ctx context.Context, tenantID, userID string) ([]string, error) {
	tid, err := roledom.ParseID(tenantID)
	if err != nil {
		return nil, err
	}
	uid, err := roledom.ParseID(userID)
	if err != nil {
		return nil, err
	}
	return s.roles.GetUserPermissions(ctx, tid, uid)
}

type aiHarness struct {
	*grbHarness
	repo     *postgres.AIAnalysisRepository
	svc      *aianalysis.Service
	triager  shared.ID // a person holding the triage preset's permissions, no approve
	viewer   shared.ID // a person with read only and no data scope
	clock    time.Time
	findings map[string]shared.ID
}

func newAIHarness(t *testing.T) *aiHarness {
	h := &aiHarness{grbHarness: newGRBHarness(t), clock: time.Now().UTC(), findings: map[string]shared.ID{}}
	db := &postgres.DB{DB: h.db}
	h.repo = postgres.NewAIAnalysisRepository(db)
	tenants := postgres.NewTenantRepository(db)
	enforcer := datascope.New(postgres.NewDataScopeRepository(db), nil, logger.NewNop())
	enforcer.SetAdminLookup(func(ctx context.Context, tenantID, userID shared.ID) (bool, error) {
		m, err := tenants.GetMembership(ctx, userID, tenantID)
		if err != nil {
			return false, err
		}
		return m.IsOwner() || m.IsAdmin(), nil
	})
	h.svc = aianalysis.New(h.repo, h.repo, apikey.NewHolderPermissions(tenants, aiRolePerms{h.roles}),
		accesscontrol.AIAnalystRoles{Roles: h.roleSvc}, enforcer, nil, nil, logger.NewNop())
	h.svc.SetClock(func() time.Time { return h.clock })

	triage, _ := permission.RoleTemplateByID(permission.TemplateAIAnalystTriage)
	perms := append(permission.ToStrings(triage.Permissions), "team:roles:assign", "team:roles:write")
	h.triager = h.user(h.tenant, "internal", "")
	h.exec(`INSERT INTO user_roles (user_id, tenant_id, role_id) VALUES ($1, $2, $3)`,
		h.triager.String(), h.tenant.String(), h.customRole(h.tenant, "ai-test-triager", false, perms...).String())
	h.viewer = h.user(h.tenant, "internal", "")
	h.exec(`INSERT INTO user_roles (user_id, tenant_id, role_id) VALUES ($1, $2, $3)`,
		h.viewer.String(), h.tenant.String(), h.customRole(h.tenant, "ai-test-reader", false, "findings:read").String())
	return h
}

func (h *aiHarness) finding(tenant shared.ID, assignee *shared.ID) shared.ID {
	id := shared.NewID()
	h.exec(`INSERT INTO findings (id, tenant_id, source, tool_name, message, severity, fingerprint, status)
		VALUES ($1::uuid, $2, 'sast', 'ai-test', 'm', 'medium', $1::text, 'new')`, id.String(), tenant.String())
	if assignee != nil {
		h.exec(`UPDATE findings SET assigned_to = $2 WHERE id = $1`, id.String(), assignee.String())
	}
	return id
}

func (h *aiHarness) create(t *testing.T, preset string, actor shared.ID, owners ...aianalysis.OwnerInput) *aidom.Analyst {
	t.Helper()
	a, err := h.svc.Create(context.Background(), aianalysis.CreateInput{Name: "AI " + preset, Preset: preset, Owners: owners}, h.actx(actor))
	if err != nil {
		t.Fatalf("create %s analyst: %v", preset, err)
	}
	return a
}

func userOwner(id shared.ID) aianalysis.OwnerInput {
	return aianalysis.OwnerInput{Kind: "user", ID: id.String()}
}

func teamOwner(id shared.ID) aianalysis.OwnerInput {
	return aianalysis.OwnerInput{Kind: "team", ID: id.String()}
}

func pausedReason(err error) aidom.PauseReason {
	var pe *aidom.PausedError
	if errors.As(err, &pe) {
		return pe.Reason
	}
	return ""
}

func TestAIAnalyst_IsAServiceAccountWithinItsRole(t *testing.T) {
	h := newAIHarness(t)
	ctx := context.Background()
	a := h.create(t, "suggest", h.owner, userOwner(h.triager))

	var kind, svcTenant string
	if err := h.db.QueryRow(`SELECT kind, service_tenant_id FROM users WHERE id = $1`, a.ID.String()).Scan(&kind, &svcTenant); err != nil {
		t.Fatal(err)
	}
	if kind != "service" || svcTenant != h.tenant.String() {
		t.Fatalf("analyst user kind=%s tenant=%s, want a service account of the organization", kind, svcTenant)
	}

	p, err := h.svc.Principal(ctx, h.tenant, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !p.Can("findings:comment") || !p.Can("findings:read") {
		t.Fatalf("suggest analyst lacks its preset: %v", p.Permissions())
	}
	if p.Can("findings:status") || p.Can("findings:severity") {
		t.Fatalf("suggest analyst may change triage state: %v", p.Permissions())
	}

	// An administrator bolts approve and verify onto the analyst's role by
	// hand: they still never become effective.
	extra := h.customRole(h.tenant, "ai-test-extra", false, "findings:approve", "findings:verify", "findings:status")
	h.exec(`INSERT INTO user_roles (user_id, tenant_id, role_id) VALUES ($1, $2, $3)`, a.ID.String(), h.tenant.String(), extra.String())
	p, err = h.svc.Principal(ctx, h.tenant, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if p.Can("findings:approve") || p.Can("findings:verify") {
		t.Fatalf("approve or verify became effective: %v", p.Permissions())
	}
	if !p.Can("findings:status") {
		t.Fatalf("status (held by the triager owner) should be effective once in the role: %v", p.Permissions())
	}
	if err := p.Require("findings:approve"); !errors.Is(err, aidom.ErrNotAllowed) {
		t.Fatalf("Require(approve) = %v, want ErrNotAllowed", err)
	}

	// The owner loses status: the analyst loses it too at the next run start.
	h.exec(`DELETE FROM role_permissions WHERE role_id = (SELECT role_id FROM user_roles WHERE user_id = $1 AND tenant_id = $2 LIMIT 1) AND permission_id = 'findings:status'`,
		h.triager.String(), h.tenant.String())
	p, err = h.svc.Principal(ctx, h.tenant, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if p.Can("findings:status") {
		t.Fatal("the analyst kept a permission no accountable owner holds any more")
	}
}

func TestAIAnalyst_RoleCannotExceedOwners(t *testing.T) {
	h := newAIHarness(t)
	_, err := h.svc.Create(context.Background(), aianalysis.CreateInput{
		Name: "AI over", Preset: "triage", Owners: []aianalysis.OwnerInput{userOwner(h.viewer)},
	}, h.actx(h.owner))
	if !errors.Is(err, shared.ErrValidation) || !strings.Contains(err.Error(), "findings:status") {
		t.Fatalf("triage analyst owned by a reader: %v, want a validation error naming the missing permission", err)
	}
	var n int
	if err := h.db.QueryRow(`SELECT count(*) FROM ai_analysts WHERE tenant_id = $1`, h.tenant.String()).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatal("a refused analyst was stored")
	}
	// The creator must be able to grant the preset (role grant ceiling).
	if _, err := h.svc.Create(context.Background(), aianalysis.CreateInput{
		Name: "AI by reader", Preset: "suggest", Owners: []aianalysis.OwnerInput{userOwner(h.triager)},
	}, h.actx(h.viewer)); err == nil {
		t.Fatal("a reader created an analyst with a role they could not grant")
	}
	var leftover int
	if err := h.db.QueryRow(`SELECT count(*) FROM users WHERE service_tenant_id = $1 AND kind = 'service'`, h.tenant.String()).Scan(&leftover); err != nil {
		t.Fatal(err)
	}
	if leftover != 0 {
		t.Fatal("a refused analyst left its service account behind")
	}
}

func TestAIAnalyst_NeverAnApprover(t *testing.T) {
	h := newAIHarness(t)
	a := h.create(t, "triage", h.owner, userOwner(h.triager))
	// Even with findings:approve written straight into its role.
	approve := h.customRole(h.tenant, "ai-test-approve", false, "findings:approve")
	h.exec(`INSERT INTO user_roles (user_id, tenant_id, role_id) VALUES ($1, $2, $3)`, a.ID.String(), h.tenant.String(), approve.String())
	approvers, err := postgres.NewScopeActorRepository(&postgres.DB{DB: h.db}).FindingApprovers(context.Background(), h.tenant)
	if err != nil {
		t.Fatal(err)
	}
	for _, ap := range approvers {
		if ap.UserID == a.ID.String() {
			t.Fatal("an AI analyst is in the approver directory")
		}
	}
}

func TestAIAnalyst_CrossTenant(t *testing.T) {
	h := newAIHarness(t)
	ctx := context.Background()
	foreignOwner := h.user(h.other, "internal", roledom.OwnerRoleID.String())
	if _, err := h.svc.Create(ctx, aianalysis.CreateInput{Name: "AI x", Preset: "suggest",
		Owners: []aianalysis.OwnerInput{userOwner(foreignOwner)}}, h.actx(h.owner)); err == nil {
		t.Fatal("a person of another organization became an owner")
	}
	if _, err := h.svc.Create(ctx, aianalysis.CreateInput{Name: "AI y", Preset: "suggest",
		Owners: []aianalysis.OwnerInput{teamOwner(h.otherTeam)}}, h.actx(h.owner)); err == nil {
		t.Fatal("a team of another organization became an owner")
	}
	a := h.create(t, "suggest", h.owner, userOwner(h.triager))
	if _, err := h.svc.Get(ctx, h.other, a.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("another organization reads the analyst: %v", err)
	}
	if _, err := h.svc.Principal(ctx, h.other, a.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("another organization resolves the analyst: %v", err)
	}
	// The schema refuses a profile on another organization's service account.
	if _, err := h.db.Exec(`INSERT INTO ai_analysts (user_id, tenant_id, attest_due_at) VALUES ($1, $2, now() + interval '1 day')`,
		a.ID.String(), h.other.String()); err == nil {
		t.Fatal("an analyst profile was attached in another organization")
	}
	// A finding of another organization is not found for the analyst.
	p, err := h.svc.Principal(ctx, h.tenant, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	foreign := h.finding(h.other, &a.ID)
	if err := p.AssertFinding(ctx, foreign); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("analyst reaches another organization's finding: %v", err)
	}
}

func TestAIAnalyst_DataScopeIsItsOwnAndAnOwners(t *testing.T) {
	h := newAIHarness(t)
	ctx := context.Background()
	a := h.create(t, "suggest", h.owner, userOwner(h.owner))
	p, err := h.svc.Principal(ctx, h.tenant, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	mine := h.finding(h.tenant, &a.ID)
	other := h.finding(h.tenant, nil)
	if err := p.AssertFinding(ctx, mine); err != nil {
		t.Fatalf("analyst refused a finding in its scope: %v", err)
	}
	if err := p.AssertFinding(ctx, other); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("analyst reached a finding outside its scope: %v", err)
	}
	// Owned only by a person who cannot see the finding: refused too.
	b := h.create(t, "suggest", h.owner, userOwner(h.triager))
	pb, err := h.svc.Principal(ctx, h.tenant, b.ID)
	if err != nil {
		t.Fatal(err)
	}
	inB := h.finding(h.tenant, &b.ID)
	if err := pb.AssertFinding(ctx, inB); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("analyst acted on a finding no accountable person can see: %v", err)
	}
}

func TestAIAnalyst_PausesWhenTheOwnerLeaves(t *testing.T) {
	h := newAIHarness(t)
	ctx := context.Background()
	a := h.create(t, "suggest", h.owner, userOwner(h.triager))
	if _, err := h.svc.Principal(ctx, h.tenant, a.ID); err != nil {
		t.Fatal(err)
	}
	h.exec(`UPDATE tenant_members SET status = 'offboarded', offboarded_at = now() WHERE user_id = $1 AND tenant_id = $2`,
		h.triager.String(), h.tenant.String())
	_, err := h.svc.Principal(ctx, h.tenant, a.ID)
	if pausedReason(err) != aidom.PauseNoActiveOwner {
		t.Fatalf("run start after the only owner left: %v, want paused no_active_owner", err)
	}
	got, err := h.svc.Get(ctx, h.tenant, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != aidom.StatusPaused || got.PauseReason != aidom.PauseNoActiveOwner {
		t.Fatalf("stored status %s/%s, want paused/no_active_owner", got.Status, got.PauseReason)
	}
	// Resume is refused while nobody answers for it; a new owner resumes it.
	if _, err := h.svc.Resume(ctx, a.ID, h.actx(h.owner)); pausedReason(err) != aidom.PauseNoActiveOwner {
		t.Fatalf("resume without an owner: %v", err)
	}
	if _, err := h.svc.ReplaceOwners(ctx, a.ID, []aianalysis.OwnerInput{userOwner(h.owner)}, h.actx(h.owner)); err != nil {
		t.Fatal(err)
	}
	if _, err := h.svc.Principal(ctx, h.tenant, a.ID); err != nil {
		t.Fatalf("analyst with a new owner still paused: %v", err)
	}
}

func TestAIAnalyst_TeamOwnerAndSweep(t *testing.T) {
	h := newAIHarness(t)
	ctx := context.Background()
	h.exec(`INSERT INTO group_members (group_id, user_id, role) VALUES ($1, $2, 'member')`, h.team.String(), h.triager.String())
	a := h.create(t, "suggest", h.owner, teamOwner(h.team))
	if _, err := h.svc.Principal(ctx, h.tenant, a.ID); err != nil {
		t.Fatalf("team-owned analyst: %v", err)
	}
	// The team's last member leaves the team: the sweep pauses the analyst.
	h.exec(`DELETE FROM group_members WHERE group_id = $1`, h.team.String())
	n, err := h.svc.Sweep(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n < 1 {
		t.Fatal("the sweep paused nothing")
	}
	got, _ := h.svc.Get(ctx, h.tenant, a.ID)
	if got.Status != aidom.StatusPaused || got.PauseReason != aidom.PauseNoActiveOwner {
		t.Fatalf("after the sweep %s/%s", got.Status, got.PauseReason)
	}
}

func TestAIAnalyst_AttestationExpiry(t *testing.T) {
	h := newAIHarness(t)
	ctx := context.Background()
	a := h.create(t, "suggest", h.owner, userOwner(h.triager))
	h.clock = h.clock.Add(aidom.AttestationPeriod + time.Hour)
	if _, err := h.svc.Principal(ctx, h.tenant, a.ID); pausedReason(err) != aidom.PauseAttestationExpired {
		t.Fatalf("run start past the attestation: %v", err)
	}
	// A person who is not accountable cannot attest; the owner can, and the
	// analyst runs again.
	if _, err := h.svc.Attest(ctx, a.ID, false, h.actx(h.viewer)); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("attest by a non-owner: %v", err)
	}
	if _, err := h.svc.Attest(ctx, a.ID, false, h.actx(h.triager)); err != nil {
		t.Fatal(err)
	}
	if _, err := h.svc.Principal(ctx, h.tenant, a.ID); err != nil {
		t.Fatalf("after attestation: %v", err)
	}
}

func TestAIAnalyst_KillSwitch(t *testing.T) {
	h := newAIHarness(t)
	ctx := context.Background()
	a := h.create(t, "suggest", h.owner, userOwner(h.triager))
	// An accountable owner may pause; a reader may not.
	if _, err := h.svc.Pause(ctx, a.ID, false, h.actx(h.viewer)); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("pause by a reader: %v", err)
	}
	if _, err := h.svc.Disable(ctx, a.ID, h.actx(h.owner)); err != nil {
		t.Fatal(err)
	}
	if _, err := h.svc.Principal(ctx, h.tenant, a.ID); pausedReason(err) != aidom.PauseAdmin {
		t.Fatalf("disabled analyst ran: %v", err)
	}
}

func TestAIAnalyst_OneLiveRunPerSubjectUnderRace(t *testing.T) {
	h := newAIHarness(t)
	ctx := context.Background()
	a := h.create(t, "suggest", h.owner, userOwner(h.owner))
	p, err := h.svc.Principal(ctx, h.tenant, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	subject := h.finding(h.tenant, &a.ID)
	start := func() error {
		_, err := h.svc.StartRun(ctx, aianalysis.StartRunInput{Principal: p, UseCase: aidom.UseCaseTriage, Kind: "triage.v1",
			SubjectType: aidom.SubjectFinding, SubjectID: subject, Executor: aidom.ExecutorBuiltin,
			DataClass: aidom.DataClassInternal, Trigger: aidom.TriggerOnDemand})
		return err
	}
	const workers = 8
	var wg sync.WaitGroup
	errs := make([]error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) { defer wg.Done(); errs[i] = start() }(i)
	}
	wg.Wait()
	won := 0
	for _, err := range errs {
		switch {
		case err == nil:
			won++
		case errors.Is(err, aidom.ErrRunInFlight):
		default:
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if won != 1 {
		t.Fatalf("%d workers won the subject, want exactly 1", won)
	}
	// A live run past its deadline gives the slot up to the next run.
	h.exec(`UPDATE ai_runs SET deadline_at = now() - interval '1 minute' WHERE tenant_id = $1 AND subject_id = $2`,
		h.tenant.String(), subject.String())
	if err := start(); err != nil {
		t.Fatalf("a run past its deadline still holds the subject: %v", err)
	}
	var timedOut int
	if err := h.db.QueryRow(`SELECT count(*) FROM ai_runs WHERE subject_id = $1 AND status = 'failed' AND error_code = 'timeout'`,
		subject.String()).Scan(&timedOut); err != nil {
		t.Fatal(err)
	}
	if timedOut != 1 {
		t.Fatalf("timed out runs = %d, want 1", timedOut)
	}
}

func TestAIAnalyst_ActivityIsLabelledAndCarriesProvenance(t *testing.T) {
	h := newAIHarness(t)
	ctx := context.Background()
	a := h.create(t, "suggest", h.owner, userOwner(h.triager))
	f := h.finding(h.tenant, &a.ID)
	runID := shared.NewID()
	pctx := aidom.WithProvenance(ctx, aidom.Provenance{AnalystID: a.ID, AnalystName: a.Name, RunID: runID,
		Executor: aidom.ExecutorBuiltin, Model: "m", Accountable: a.Owners})
	act, err := vulnerability.NewFindingActivity(h.tenant, f, vulnerability.ActivityCommentAdded, &a.ID,
		vulnerability.ActorTypeUser, map[string]any{"content": "x"}, vulnerability.SourceAPI, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := postgres.NewFindingActivityRepository(&postgres.DB{DB: h.db}).Create(pctx, act); err != nil {
		t.Fatal(err)
	}
	var actorType, source, run string
	if err := h.db.QueryRow(`SELECT actor_type, source, source_metadata->'ai'->>'run_id' FROM finding_activities WHERE id = $1`,
		act.ID().String()).Scan(&actorType, &source, &run); err != nil {
		t.Fatal(err)
	}
	if actorType != "ai" || source != "ai_analyst" || run != runID.String() {
		t.Fatalf("activity actor_type=%s source=%s run=%s", actorType, source, run)
	}
	// Any path that writes a row for the analyst, without provenance, is
	// still labeled AI by the database.
	h.exec(`INSERT INTO finding_activities (tenant_id, finding_id, activity_type, actor_type, actor_id, changes)
		VALUES ($1, $2, 'comment_added', 'user', $3, '{}')`, h.tenant.String(), f.String(), a.ID.String())
	var n int
	if err := h.db.QueryRow(`SELECT count(*) FROM finding_activities WHERE finding_id = $1 AND actor_type = 'ai'`, f.String()).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("AI-labeled rows = %d, want 2", n)
	}
}

func TestAIAnalyst_IsNotASeat(t *testing.T) {
	h := newAIHarness(t)
	usage := func() int {
		u, err := postgres.NewLimitsRepository(&postgres.DB{DB: h.db}).Usage(context.Background(), h.tenant, false)
		if err != nil {
			t.Fatal(err)
		}
		return u[limits.Seats]
	}
	before := usage()
	h.create(t, "suggest", h.owner, userOwner(h.triager))
	if after := usage(); after != before {
		t.Fatalf("seats %d -> %d: an AI analyst took a seat", before, after)
	}
}
