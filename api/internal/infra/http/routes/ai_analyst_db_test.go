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
	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/datascope"
	"github.com/openctemio/openctem/api/internal/app/finding"
	tenantapp "github.com/openctemio/openctem/api/internal/app/tenant"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	aidom "github.com/openctemio/openctem/api/pkg/domain/aianalysis"
	"github.com/openctemio/openctem/api/pkg/domain/limits"
	roledom "github.com/openctemio/openctem/api/pkg/domain/role"
	"github.com/openctemio/openctem/api/pkg/domain/serviceaccount"
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
		enforcer, nil, nil, logger.NewNop())
	h.svc.SetClock(func() time.Time { return h.clock })

	perms := aidom.PresetTriage.Permissions()
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

	// Nobody can widen an analyst through a role: it holds none, and the
	// schema refuses one (approve and verify would be denied anyway).
	extra := h.customRole(h.tenant, "ai-test-extra", false, "findings:approve", "findings:verify", "findings:status")
	if _, err := h.db.Exec(`INSERT INTO user_roles (user_id, tenant_id, role_id) VALUES ($1, $2, $3)`,
		a.ID.String(), h.tenant.String(), extra.String()); err == nil {
		t.Fatal("a role was attached to an AI analyst")
	}
	if err := p.Require("findings:approve"); !errors.Is(err, aidom.ErrNotAllowed) {
		t.Fatalf("Require(approve) = %v, want ErrNotAllowed", err)
	}
	// The triage preset holds status while an owner holds it.
	if _, err := h.svc.ChangePreset(ctx, a.ID, "triage", h.actx(h.owner)); err != nil {
		t.Fatal(err)
	}
	p, err = h.svc.Principal(ctx, h.tenant, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !p.Can("findings:status") {
		t.Fatalf("triage analyst lacks status held by its owner: %v", p.Permissions())
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
	}, h.actx(h.viewer)); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("a reader created an analyst with permissions they do not hold: %v", err)
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
	approvers, err := postgres.NewScopeActorRepository(&postgres.DB{DB: h.db}).FindingApprovers(context.Background(), h.tenant)
	if err != nil {
		t.Fatal(err)
	}
	for _, ap := range approvers {
		if ap.UserID == a.ID.String() {
			t.Fatal("an AI analyst is in the approver directory")
		}
	}
	// A team that grants findings:approve does not make it one either.
	approve := h.customRole(h.tenant, "ai-test-approve", false, "findings:read", "findings:approve")
	h.exec(`INSERT INTO group_role_bindings (tenant_id, group_id, role_id) VALUES ($1, $2, $3)`, h.tenant.String(), h.team.String(), approve.String())
	h.exec(`INSERT INTO group_members (group_id, user_id, role) VALUES ($1, $2, 'member')`, h.team.String(), a.ID.String())
	approvers, err = postgres.NewScopeActorRepository(&postgres.DB{DB: h.db}).FindingApprovers(context.Background(), h.tenant)
	if err != nil {
		t.Fatal(err)
	}
	for _, ap := range approvers {
		if ap.UserID == a.ID.String() {
			t.Fatal("an AI analyst in an approving team is in the approver directory")
		}
	}
	p, err := h.svc.Principal(context.Background(), h.tenant, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if p.Can("findings:approve") {
		t.Fatal("a team role gave the analyst findings:approve")
	}
}

// An analyst acts only through the platform: no API key, MCP grant, role,
// sign-in identity or password, whatever path tries to give it one.
func TestAIAnalyst_HasNoCredentialOfItsOwn(t *testing.T) {
	h := newAIHarness(t)
	ctx := context.Background()
	a := h.create(t, "suggest", h.owner, userOwner(h.triager))
	if _, err := h.db.Exec(`INSERT INTO api_keys (id, tenant_id, user_id, name, key_hash, key_prefix, status) VALUES ($1, $2, $3, 'k', $4, 'oct_test', 'active')`,
		shared.NewID().String(), h.tenant.String(), a.ID.String(), "h-"+shared.NewID().String()); err == nil {
		t.Error("an API key was stored for an AI analyst")
	}
	client := shared.NewID()
	h.exec(`INSERT INTO mcp_oauth_clients (id, client_id, kind, tenant_id, name, redirect_uris) VALUES ($1, $2, 'organization', $3, 'c', ARRAY['https://c.example/cb'])`,
		client.String(), "client-"+client.String(), h.tenant.String())
	if _, err := h.db.Exec(`INSERT INTO mcp_oauth_grants (tenant_id, user_id, client_ref, resource, scopes, expires_at) VALUES ($1, $2, $3, 'https://api.example', ARRAY['findings:read'], now() + interval '1 day')`,
		h.tenant.String(), a.ID.String(), client.String()); err == nil {
		t.Error("an MCP grant was stored for an AI analyst")
	}
	if _, err := h.db.Exec(`INSERT INTO user_identities (user_id, issuer, subject) VALUES ($1, 'https://idp.example', 'sub-ai')`, a.ID.String()); err == nil {
		t.Error("a sign-in identity was stored for an AI analyst")
	}
	var hasPassword bool
	if err := h.db.QueryRow(`SELECT password_hash IS NOT NULL FROM users WHERE id = $1`, a.ID.String()).Scan(&hasPassword); err != nil {
		t.Fatal(err)
	}
	if hasPassword {
		t.Error("an AI analyst has a password")
	}
	// The service-account screens neither mint its keys nor delete it.
	db := &postgres.DB{DB: h.db}
	sa := accesscontrol.NewServiceAccountService(postgres.NewServiceAccountRepository(db), nil, logger.NewNop())
	got, err := sa.Get(ctx, h.tenant.String(), a.ID.String())
	if err != nil {
		t.Fatal(err)
	}
	if !got.AIAnalyst {
		t.Error("the service-account view does not mark the analyst")
	}
	if err := sa.Delete(ctx, a.ID.String(), h.actx(h.owner)); !errors.Is(err, serviceaccount.ErrAIAnalyst) {
		t.Errorf("service-account delete of an analyst: %v", err)
	}
	// A plain service account with a key never becomes an analyst.
	plain, err := sa.Create(ctx, accesscontrol.CreateServiceAccountInput{Name: "bridge"}, h.actx(h.owner))
	if err != nil {
		t.Fatal(err)
	}
	h.exec(`INSERT INTO api_keys (id, tenant_id, user_id, name, key_hash, key_prefix, status) VALUES ($1, $2, $3, 'k', $4, 'oct_test', 'active')`,
		shared.NewID().String(), h.tenant.String(), plain.ID.String(), "h-"+shared.NewID().String())
	if _, err := h.db.Exec(`INSERT INTO ai_analysts (user_id, tenant_id, attest_due_at) VALUES ($1, $2, now() + interval '1 day')`,
		plain.ID.String(), h.tenant.String()); err == nil {
		t.Error("a service account with an API key became an AI analyst")
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

// An AI analyst never lowers risk alone: with the organization's
// false-positive and acceptance levels off (a person decides alone), an
// analyst's false positive and severity downgrade still wait for a person,
// even if a caller claimed it could approve.
func TestAIAnalyst_RiskLoweringNeedsAPersonWithApprovalOff_DB(t *testing.T) {
	h := newFindingApprovalHarness(t, func(svc *finding.VulnerabilityService, vh *handler.VulnerabilityHandler, db *postgres.DB) {
		log := logger.NewNop()
		ts := tenantapp.NewTenantService(postgres.NewTenantRepository(db), log,
			tenantapp.WithTenantAuditService(auditapp.NewAuditService(postgres.NewAuditRepository(db), log)))
		actors := postgres.NewScopeActorRepository(db)
		svc.SetSoloApproval(actors, nil, ts)
		svc.SetApprovalNotifier(actors, nil, nil, "")
		vh.SetFindingApprovalSettings(ts)
		svc.SetAIAnalystChecker(postgres.NewAIAnalysisRepository(db))
		svc.SetSeverityRequestRepository(postgres.NewSeverityRequestRepository(db))
	})
	ctx := context.Background()
	org := h.tenantWithFindings()
	setFPLevel(h, org, `{"fp_approval":"off","accept_approval":"off"}`)
	person := h.member(org, "admin")

	analyst := shared.NewID().String()
	h.exec(`INSERT INTO users (id, email, name, kind, service_tenant_id) VALUES ($1, $2, 'AI', 'service', $3)`,
		analyst, "svc-"+analyst+"@service-accounts.invalid", org)
	t.Cleanup(func() { _, _ = h.db.ExecContext(ctx, `DELETE FROM users WHERE id = $1`, analyst) })
	h.exec(`INSERT INTO tenant_members (user_id, tenant_id, role) VALUES ($1, $2, 'viewer')`, analyst, org)
	h.exec(`DELETE FROM user_roles WHERE user_id = $1`, analyst)
	h.exec(`INSERT INTO ai_analysts (user_id, tenant_id, preset, attest_due_at) VALUES ($1, $2, 'triage', now() + interval '90 days')`, analyst, org)

	// A person under level off decides alone (control).
	if status, single, _ := requestFP(h, person, h.newFinding(org, "low")); status != "approved" || !single {
		t.Fatalf("control: a person under level off: %s %v", status, single)
	}
	ap, err := h.svc.RequestApproval(ctx, finding.RequestApprovalInput{
		TenantID: org, FindingID: h.newFinding(org, "low"), RequestedStatus: "false_positive",
		Justification: "the AI thinks this is test code", RequestedBy: analyst, ClosureReason: "test_or_example_code",
		CanApprove: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if ap.Status != vulnerability.ApprovalStatusPending {
		t.Fatalf("an AI analyst's false positive under level off is %s, want pending", ap.Status)
	}
	res, err := h.svc.ChangeFindingSeverity(ctx, finding.ChangeSeverityInput{
		TenantID: org, FindingID: h.newFinding(org, "high"), ActorID: analyst, Severity: "low",
		Reason: "the AI thinks the impact is low", CanApprove: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Applied || res.Request == nil {
		t.Fatal("an AI analyst lowered a severity without a person")
	}
}

// Read-only AI assistance (explain, summarize, translate, questions) runs
// under the viewer's own permissions and writes nothing: in an assistance
// context every finding command is refused before it writes, even for a
// viewer who could make the change by hand, and no analyst principal can be
// resolved. The marker exists only in process (no token or header sets it).
func TestAIAssist_CannotWrite_DB(t *testing.T) {
	h := newFindingApprovalHarness(t, func(svc *finding.VulnerabilityService, vh *handler.VulnerabilityHandler, db *postgres.DB) {
		log := logger.NewNop()
		ts := tenantapp.NewTenantService(postgres.NewTenantRepository(db), log,
			tenantapp.WithTenantAuditService(auditapp.NewAuditService(postgres.NewAuditRepository(db), log)))
		actors := postgres.NewScopeActorRepository(db)
		svc.SetSoloApproval(actors, nil, ts)
		svc.SetApprovalNotifier(actors, nil, nil, "")
		vh.SetFindingApprovalSettings(ts)
		svc.SetSeverityRequestRepository(postgres.NewSeverityRequestRepository(db))
		svc.SetCommentRepository(postgres.NewFindingCommentRepository(db))
	})
	org := h.tenantWithFindings()
	viewer := h.member(org, "admin")
	f := h.newFinding(org, "high")
	ctx := aidom.WithAssist(context.Background())

	if _, err := h.svc.AddFindingCommentWithInput(ctx, finding.AddFindingCommentInput{
		TenantID: org, FindingID: f, AuthorID: viewer.id, Content: "drafted silently", ActingUserID: viewer.id, IsAdmin: true,
	}); !errors.Is(err, aidom.ErrAssistReadOnly) {
		t.Errorf("comment in an assistance context: %v", err)
	}
	if _, err := h.svc.UpdateFindingStatus(ctx, f, org, finding.UpdateFindingStatusInput{Status: "in_progress", ActorID: viewer.id}); !errors.Is(err, aidom.ErrAssistReadOnly) {
		t.Errorf("status in an assistance context: %v", err)
	}
	if _, err := h.svc.ChangeFindingSeverity(ctx, finding.ChangeSeverityInput{
		TenantID: org, FindingID: f, ActorID: viewer.id, Severity: "critical", Reason: "assist", CanApprove: true,
	}); !errors.Is(err, aidom.ErrAssistReadOnly) {
		t.Errorf("severity in an assistance context: %v", err)
	}
	if _, err := h.svc.RequestApproval(ctx, finding.RequestApprovalInput{
		TenantID: org, FindingID: f, RequestedStatus: "false_positive", Justification: "assist",
		RequestedBy: viewer.id, ClosureReason: "test_or_example_code", CanApprove: true,
	}); !errors.Is(err, aidom.ErrAssistReadOnly) {
		t.Errorf("approval request in an assistance context: %v", err)
	}
	var status, sev string
	var comments, approvals, activities int
	if err := h.db.QueryRow(`SELECT status, severity,
		(SELECT count(*) FROM finding_comments WHERE finding_id = $1::uuid),
		(SELECT count(*) FROM finding_status_approvals WHERE finding_id = $1::uuid),
		(SELECT count(*) FROM finding_activities WHERE finding_id = $1::uuid)
		FROM findings WHERE id = $1::uuid`, f).Scan(&status, &sev, &comments, &approvals, &activities); err != nil {
		t.Fatal(err)
	}
	if status != "confirmed" || sev != "high" || comments+approvals+activities != 0 {
		t.Fatalf("assistance wrote: status=%s severity=%s comments=%d approvals=%d activities=%d", status, sev, comments, approvals, activities)
	}
	// Outside the assistance context the same viewer may comment (control).
	if _, err := h.svc.AddFindingCommentWithInput(context.Background(), finding.AddFindingCommentInput{
		TenantID: org, FindingID: f, AuthorID: viewer.id, Content: "posted by the person", ActingUserID: viewer.id, IsAdmin: true,
	}); err != nil {
		t.Fatalf("control comment: %v", err)
	}
	// No analyst principal is resolved in an assistance context.
	ah := newAIHarness(t)
	a := ah.create(t, "suggest", ah.owner, userOwner(ah.triager))
	if _, err := ah.svc.Principal(aidom.WithAssist(context.Background()), ah.tenant, a.ID); !errors.Is(err, aidom.ErrAssistReadOnly) {
		t.Fatalf("principal in an assistance context: %v", err)
	}
}
