package integration

// A CI trust adds the repositories it trusts to scope, on a real database
// (docs/rfcs/RFC-054-scope-model.md, "Repository entries and CI trusts"):
// confirmed at once, evidence from a verified run, the opt-in proof setting,
// the lifecycle with the trust, the guards, and tenant isolation.

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	cirunapp "github.com/openctemio/openctem/api/internal/app/cirun"
	scopeapp "github.com/openctemio/openctem/api/internal/app/scope"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/cirun"
	"github.com/openctemio/openctem/api/pkg/domain/scangov"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// scopeSettingsFake answers each tenant's scope settings.
type scopeSettingsFake struct {
	mu sync.Mutex
	m  map[string]tenant.ScopeSettings
}

func (f *scopeSettingsFake) GetScopeSettings(_ context.Context, tenantID string) (*tenant.ScopeSettings, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s := f.m[tenantID]
	return &s, nil
}

func (f *scopeSettingsFake) set(tenantID shared.ID, s tenant.ScopeSettings) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.m[tenantID.String()] = s
}

// govFake answers the organization's scan approval mode.
type govFake struct {
	mu   sync.Mutex
	mode scangov.Mode
}

func (g *govFake) ScanGovernanceMode(context.Context, shared.ID) (scangov.Mode, string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.mode, scangov.SourceOrganization
}

func (g *govFake) set(m scangov.Mode) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.mode = m
}

type ciScopeRig struct {
	*ciRig
	scope    *scopeapp.Service
	settings *scopeSettingsFake
	gov      *govFake
	host     string
	// admin may change CI trust and scope and approve scope entries;
	// ciOnly holds scans:ci:write but no scope permission (a custom role).
	admin, ciOnly cirunapp.Actor
}

// scopeTrust creates a trust as an administrator who may change scope.
func (r *ciScopeRig) scopeTrust(tenantID shared.ID, rules cirun.Rules) *cirun.TrustConfig {
	r.t.Helper()
	c, err := r.svc.CreateTrustConfig(context.Background(), tenantID, cirunapp.TrustConfigInput{
		Name: "gitlab-" + shared.NewID().String()[28:], Provider: "gitlab", Issuer: r.idp.srv.URL, Rules: rules,
	}, r.admin)
	if err != nil {
		r.t.Fatalf("create trust config: %v", err)
	}
	return c
}

func newCIScopeRig(t *testing.T) *ciScopeRig {
	t.Helper()
	r := newCIRig(t)
	scope := scopeapp.NewService(postgres.NewScopeTargetRepository(r.db), postgres.NewScopeExclusionRepository(r.db),
		postgres.NewAssetRepository(r.db), logger.NewNop())
	scope.SetCITrustLinks(postgres.NewScopeCITrustLinkRepository(r.db))
	settings := &scopeSettingsFake{m: map[string]tenant.ScopeSettings{}}
	scope.SetEntryPolicy(settings, nil, nil)
	scope.SetStepUpGate(recentAuth{})
	gov := &govFake{mode: scangov.ModeOff} // the default: scan approval off
	scope.SetGovernance(gov)
	r.svc.SetScopeLinker(scope)
	admin := cirunapp.Actor{UserID: seedActUser(t, r.db.DB).String(), Email: "admin@acme.test", ScopeWrite: true, ScopeApprove: true}
	ciOnly := cirunapp.Actor{UserID: seedActUser(t, r.db.DB).String(), Email: "ci@acme.test"}
	return &ciScopeRig{ciRig: r, scope: scope, settings: settings, gov: gov, admin: admin, ciOnly: ciOnly,
		host: strings.ToLower(strings.TrimPrefix(r.idp.srv.URL, "https://"))}
}

// entry is the tenant's repository entry with this pattern (nil: none).
func (r *ciScopeRig) entry(tenantID shared.ID, pattern string) *scopedom.Target {
	r.t.Helper()
	ex, err := postgres.NewScopeTargetRepository(r.db).FindByPattern(context.Background(), tenantID, scopedom.TargetTypeRepository, pattern)
	if err != nil {
		r.t.Fatal(err)
	}
	if ex == nil {
		return nil
	}
	got, err := r.scope.GetTarget(context.Background(), tenantID.String(), ex.ID.String())
	if err != nil {
		r.t.Fatal(err)
	}
	return got
}

func (r *ciScopeRig) links(tenantID, trustID shared.ID) []scopedom.CITrustLink {
	r.t.Helper()
	l, err := r.svc.TrustScope(context.Background(), tenantID, trustID)
	if err != nil {
		r.t.Fatal(err)
	}
	return l
}

// Creating a trust adds its namespace to scope at once, confirmed, and a
// verified run leaves its evidence on the link.
func TestCITrustScope_ConfirmedAtOnceWithEvidence(t *testing.T) {
	r := newCIScopeRig(t)
	ctx := context.Background()
	cfg := r.scopeTrust(r.tenant, cirun.Rules{Owners: []string{"acme"}})
	pattern := r.host + "/acme/*"

	e := r.entry(r.tenant, pattern)
	if e == nil || e.Status() != scopedom.StatusActive || e.Origin() != scopedom.OriginCITrust {
		t.Fatalf("entry after trust create: %+v", e)
	}
	links := r.links(r.tenant, cfg.ID)
	if len(links) != 1 || links[0].Pattern != pattern || links[0].TargetID == nil || !links[0].TargetID.Equals(e.ID()) ||
		links[0].SeenAt != nil {
		t.Fatalf("links: %+v", links)
	}
	if r.auditCount(r.tenant, "ci_trust_config.updated", "created "+pattern) != 1 {
		t.Fatal("scope change not audited on the trust")
	}

	// A verified run under it is evidence (once).
	code, ex := r.exchange(r.tenant, r.idp.token(t, cfg.Audience, "acme/api", "main", strings.Repeat("a", 40), nil))
	if code != http.StatusCreated {
		t.Fatalf("exchange: %d %v", code, ex)
	}
	links = r.links(r.tenant, cfg.ID)
	if links[0].SeenAt == nil || links[0].SeenRepository != r.host+"/acme/api" || links[0].SeenRunID == nil ||
		links[0].SeenRunID.String() != ex["run_id"] {
		t.Fatalf("evidence: %+v", links[0])
	}
	first := *links[0].SeenAt
	if code, _ := r.exchange(r.tenant, r.idp.token(t, cfg.Audience, "acme/web", "main", strings.Repeat("b", 40), nil)); code != http.StatusCreated {
		t.Fatalf("second exchange: %d", code)
	}
	if again := r.links(r.tenant, cfg.ID); !again[0].SeenAt.Equal(first) || again[0].SeenRepository != r.host+"/acme/api" {
		t.Fatalf("evidence overwritten: %+v", again[0])
	}

	// The entry is managed: its scope, status and existence change through
	// the trust only; its description stays editable.
	if _, err := r.scope.UpdateTarget(ctx, e.ID().String(), r.tenant.String(), scopeapp.UpdateTargetInput{MaxTier: strPtr("t2")}); !errors.Is(err, scopedom.ErrCITrustManaged) {
		t.Errorf("update tier: %v, want CI_TRUST_MANAGED", err)
	}
	if _, err := r.scope.DeactivateTarget(ctx, e.ID().String(), r.tenant.String()); !errors.Is(err, scopedom.ErrCITrustManaged) {
		t.Errorf("deactivate: %v, want CI_TRUST_MANAGED", err)
	}
	if err := r.scope.DeleteTarget(ctx, e.ID().String(), r.tenant.String()); !errors.Is(err, scopedom.ErrCITrustManaged) {
		t.Errorf("delete: %v, want CI_TRUST_MANAGED", err)
	}
	if _, err := r.scope.UpdateTarget(ctx, e.ID().String(), r.tenant.String(), scopeapp.UpdateTargetInput{Description: strPtr("API repos")}); err != nil {
		t.Errorf("description: %v", err)
	}
}

// With the organization's opt-in proof setting, a trust's entry waits
// inactive until a verified run under it.
func TestCITrustScope_RequiresProofOptIn(t *testing.T) {
	r := newCIScopeRig(t)
	r.settings.set(r.tenant, tenant.ScopeSettings{CIScopeRequiresProof: true})
	cfg := r.scopeTrust(r.tenant, cirun.Rules{Owners: []string{"acme"}})
	pattern := r.host + "/acme/*"
	if e := r.entry(r.tenant, pattern); e == nil || e.Status() != scopedom.StatusInactive {
		t.Fatalf("entry before proof: %+v", e)
	}
	active, _ := r.scope.ListActiveTargets(context.Background(), r.tenant.String())
	for _, a := range active {
		if a.Pattern() == pattern {
			t.Fatal("an unproven entry authorizes")
		}
	}
	// A person cannot put it into effect around the proof.
	e := r.entry(r.tenant, pattern)
	if _, err := r.scope.ActivateTarget(context.Background(), e.ID().String(), r.tenant.String(), scopeapp.Actor{UserID: shared.NewID().String(), CanApprove: true}); !errors.Is(err, scopedom.ErrCITrustManaged) {
		t.Fatalf("activate before proof: %v, want CI_TRUST_MANAGED", err)
	}
	// A run from another namespace proves nothing for it.
	if code, _ := r.exchange(r.tenant, r.idp.token(t, cfg.Audience, "other/api", "main", strings.Repeat("c", 40), nil)); code != http.StatusUnauthorized {
		t.Fatalf("other namespace: %d", code)
	}
	if e := r.entry(r.tenant, pattern); e.Status() != scopedom.StatusInactive {
		t.Fatal("a refused run proved the entry")
	}
	if code, _ := r.exchange(r.tenant, r.idp.token(t, cfg.Audience, "acme/sub/api", "main", strings.Repeat("d", 40), nil)); code != http.StatusCreated {
		t.Fatalf("exchange: %d", code)
	}
	if e := r.entry(r.tenant, pattern); e.Status() != scopedom.StatusActive {
		t.Fatalf("entry after proof: %s", e.Status())
	}
}

// The entries follow the trust: an edit moves them, disabling or deleting
// the trust retires them, and an equal entry a person made is linked, never
// duplicated, and survives the trust.
func TestCITrustScope_Lifecycle(t *testing.T) {
	r := newCIScopeRig(t)
	ctx := context.Background()
	manual, err := r.scope.CreateTarget(ctx, scopeapp.CreateTargetInput{TenantID: r.tenant.String(), TargetType: "repository",
		Pattern: r.host + "/beta/*"})
	if err != nil {
		t.Fatal(err)
	}
	cfg := r.scopeTrust(r.tenant, cirun.Rules{Owners: []string{"acme"}})
	acme := r.host + "/acme/*"
	acmeEntry := r.entry(r.tenant, acme)

	// Edit: acme -> beta. acme's entry is retired; beta's existing manual
	// entry is linked as it is.
	in := cirunapp.TrustConfigInput{Name: cfg.Name, Provider: "gitlab", Issuer: cfg.Issuer, Audience: cfg.Audience,
		Rules: cirun.Rules{Owners: []string{"beta"}}}
	if _, err := r.svc.UpdateTrustConfig(ctx, r.tenant, cfg.ID, in, r.admin); err != nil {
		t.Fatal(err)
	}
	if r.entry(r.tenant, acme) != nil {
		t.Fatal("the dropped namespace's entry was not retired")
	}
	links := r.links(r.tenant, cfg.ID)
	if len(links) != 1 || links[0].TargetID == nil || !links[0].TargetID.Equals(manual.ID()) {
		t.Fatalf("links after edit: %+v", links)
	}
	if b := r.entry(r.tenant, r.host+"/beta/*"); b.Origin() == scopedom.OriginCITrust || !b.ID().Equals(manual.ID()) {
		t.Fatalf("the manual entry was replaced: %+v", b)
	}
	// The person's entry stays theirs to change.
	if _, err := r.scope.DeactivateTarget(ctx, manual.ID().String(), r.tenant.String()); err != nil {
		t.Fatalf("deactivate the manual entry: %v", err)
	}
	if _, err := r.scope.ActivateTarget(ctx, manual.ID().String(), r.tenant.String(), scopeapp.Actor{}); err != nil {
		t.Fatalf("reactivate the manual entry: %v", err)
	}

	// Disable: managed entries retire (none here but the manual one stays).
	in.Rules = cirun.Rules{Owners: []string{"acme", "beta"}}
	if _, err := r.svc.UpdateTrustConfig(ctx, r.tenant, cfg.ID, in, r.admin); err != nil {
		t.Fatal(err)
	}
	if e := r.entry(r.tenant, acme); e == nil || e.Status() != scopedom.StatusActive || e.ID().Equals(acmeEntry.ID()) {
		t.Fatalf("re-added namespace: %+v", e)
	}
	off := false
	in.Enabled = &off
	if _, err := r.svc.UpdateTrustConfig(ctx, r.tenant, cfg.ID, in, r.admin); err != nil {
		t.Fatal(err)
	}
	if r.entry(r.tenant, acme) != nil || len(r.links(r.tenant, cfg.ID)) != 0 {
		t.Fatal("a disabled trust still manages scope")
	}
	if r.entry(r.tenant, r.host+"/beta/*") == nil {
		t.Fatal("the person's entry was retired with the trust")
	}

	// "Trust and add to scope" off: the trust manages nothing.
	on, noScope := true, false
	in.Enabled, in.ManageScope = &on, &noScope
	if _, err := r.svc.UpdateTrustConfig(ctx, r.tenant, cfg.ID, in, r.admin); err != nil {
		t.Fatal(err)
	}
	if r.entry(r.tenant, acme) != nil {
		t.Fatal("manage_scope=false created an entry")
	}

	// Delete: retired first, the links go with the trust.
	in.ManageScope = &on
	if _, err := r.svc.UpdateTrustConfig(ctx, r.tenant, cfg.ID, in, r.admin); err != nil {
		t.Fatal(err)
	}
	if r.entry(r.tenant, acme) == nil {
		t.Fatal("manage_scope back on did not add the namespace")
	}
	if err := r.svc.DeleteTrustConfig(ctx, r.tenant, cfg.ID, cirunapp.Actor{}); err != nil {
		t.Fatal(err)
	}
	if r.entry(r.tenant, acme) != nil {
		t.Fatal("a deleted trust's entry stayed")
	}
	var n int
	if err := r.db.QueryRowContext(ctx, `SELECT count(*) FROM scope_target_ci_trusts WHERE tenant_id = $1`, r.tenant.String()).Scan(&n); err != nil || n != 0 {
		t.Fatalf("links after delete: %d %v", n, err)
	}

	// Two trusts on one namespace share one entry; it retires with the last.
	a := r.scopeTrust(r.tenant, cirun.Rules{Owners: []string{"gamma"}})
	b := r.scopeTrust(r.tenant, cirun.Rules{Owners: []string{"gamma"}})
	gamma := r.entry(r.tenant, r.host+"/gamma/*")
	if gamma == nil || len(r.links(r.tenant, a.ID)) != 1 || len(r.links(r.tenant, b.ID)) != 1 {
		t.Fatal("overlapping trusts")
	}
	if err := r.svc.DeleteTrustConfig(ctx, r.tenant, a.ID, cirunapp.Actor{}); err != nil {
		t.Fatal(err)
	}
	if r.entry(r.tenant, r.host+"/gamma/*") == nil {
		t.Fatal("the shared entry left with the first trust")
	}
	if err := r.svc.DeleteTrustConfig(ctx, r.tenant, b.ID, cirunapp.Actor{}); err != nil {
		t.Fatal(err)
	}
	if r.entry(r.tenant, r.host+"/gamma/*") != nil {
		t.Fatal("the shared entry stayed after the last trust")
	}
}

// Tenants are isolated: each trust has its own entry, another tenant's run
// is never evidence, and another tenant's ids are not readable.
func TestCITrustScope_CrossTenant(t *testing.T) {
	r := newCIScopeRig(t)
	ctx := context.Background()
	a := r.scopeTrust(r.tenant, cirun.Rules{Owners: []string{"acme"}})
	b := r.scopeTrust(r.other, cirun.Rules{Owners: []string{"acme"}})
	pattern := r.host + "/acme/*"
	ea, eb := r.entry(r.tenant, pattern), r.entry(r.other, pattern)
	if ea == nil || eb == nil || ea.ID().Equals(eb.ID()) {
		t.Fatal("each tenant gets its own entry")
	}
	// Tenant A's run (A's audience) is evidence for A only.
	if code, _ := r.exchange(r.tenant, r.idp.token(t, a.Audience, "acme/api", "main", strings.Repeat("e", 40), nil)); code != http.StatusCreated {
		t.Fatalf("exchange: %d", code)
	}
	if r.links(r.tenant, a.ID)[0].SeenAt == nil || r.links(r.other, b.ID)[0].SeenAt != nil {
		t.Fatal("evidence crossed tenants")
	}
	// A token minted for A is refused by B.
	if code, _ := r.exchange(r.other, r.idp.token(t, a.Audience, "acme/api", "main", strings.Repeat("f", 40), nil)); code != http.StatusUnauthorized {
		t.Fatalf("A's token at B: %d", code)
	}
	// B cannot read A's links, nor see them on its entries.
	if l := r.links(r.other, a.ID); len(l) != 0 {
		t.Fatalf("B read A's links: %+v", l)
	}
	m, err := r.scope.CITrustLinksFor(ctx, r.other, []shared.ID{ea.ID()})
	if err != nil || len(m) != 0 {
		t.Fatalf("B saw links of A's entry: %v %v", m, err)
	}
	// A link row cannot point at another tenant's entry or trust.
	if _, err := r.db.ExecContext(ctx, `INSERT INTO scope_target_ci_trusts (tenant_id, trust_config_id, pattern, target_id)
		VALUES ($1, $2, 'x.example/y/*', $3)`, r.other.String(), b.ID.String(), ea.ID().String()); err == nil {
		t.Fatal("a link crossed tenants")
	}
	// B deleting its trust leaves A's entry alone.
	if err := r.svc.DeleteTrustConfig(ctx, r.other, b.ID, cirunapp.Actor{}); err != nil {
		t.Fatal(err)
	}
	if r.entry(r.tenant, pattern) == nil || r.entry(r.other, pattern) != nil {
		t.Fatal("retiring B's entry touched A")
	}
}

// The owner's example: trusting gitlab.com/0xmanhnv adds gitlab.com/0xmanhnv/*.
func TestCITrustScope_PublicHostNamespace(t *testing.T) {
	r := newCIScopeRig(t)
	c, err := r.svc.CreateTrustConfig(context.Background(), r.tenant, cirunapp.TrustConfigInput{
		Name: "gitlab.com", Provider: "gitlab", Rules: cirun.Rules{Owners: []string{"0xmanhnv"}},
	}, r.admin)
	if err != nil {
		t.Fatal(err)
	}
	if e := r.entry(r.tenant, "gitlab.com/0xmanhnv/*"); e == nil || e.Status() != scopedom.StatusActive {
		t.Fatalf("entry: %+v (links %+v)", e, r.links(r.tenant, c.ID))
	}
}

func strPtr(s string) *string { return &s }

// Adding a trust's repositories to scope needs the scope write permission:
// a custom role with only scans:ci:write cannot widen scope through a trust.
func TestCITrustScope_NeedsScopeWrite(t *testing.T) {
	r := newCIScopeRig(t)
	ctx := context.Background()
	on := true
	in := cirunapp.TrustConfigInput{Name: "ci-only", Provider: "gitlab", Issuer: r.idp.srv.URL,
		Rules: cirun.Rules{Owners: []string{"acme"}}, ManageScope: &on}
	if _, err := r.svc.CreateTrustConfig(ctx, r.tenant, in, r.ciOnly); !errors.Is(err, cirunapp.ErrManageScopeForbidden) {
		t.Fatalf("manage_scope=true without scope write: %v", err)
	}
	// Left out, it defaults to off for this caller: the trust works, scope
	// is untouched.
	in.ManageScope = nil
	c, err := r.svc.CreateTrustConfig(ctx, r.tenant, in, r.ciOnly)
	if err != nil {
		t.Fatal(err)
	}
	if c.ManageScope || r.entry(r.tenant, r.host+"/acme/*") != nil {
		t.Fatalf("a caller without scope write added scope: %+v", c)
	}
	// An administrator turns it on; afterwards the CI-only caller may rename
	// it or narrow it, never widen it.
	in.ManageScope = &on
	if _, err := r.svc.UpdateTrustConfig(ctx, r.tenant, c.ID, in, r.admin); err != nil {
		t.Fatal(err)
	}
	in.ManageScope, in.Name = nil, "renamed"
	if _, err := r.svc.UpdateTrustConfig(ctx, r.tenant, c.ID, in, r.ciOnly); err != nil {
		t.Fatalf("rename: %v", err)
	}
	in.Rules = cirun.Rules{Owners: []string{"acme", "beta"}}
	if _, err := r.svc.UpdateTrustConfig(ctx, r.tenant, c.ID, in, r.ciOnly); !errors.Is(err, cirunapp.ErrManageScopeForbidden) {
		t.Fatalf("widen without scope write: %v", err)
	}
	if r.entry(r.tenant, r.host+"/beta/*") != nil {
		t.Fatal("a refused change widened scope")
	}
}

// The entries follow the organization's scope approval rules as the person
// who saved the trust: under Strict, an approver's entry waits for its
// approvals and anyone else's is not added.
func TestCITrustScope_FollowsGovernance(t *testing.T) {
	r := newCIScopeRig(t)
	r.gov.set(scangov.ModeStrict)
	cfg := r.scopeTrust(r.tenant, cirun.Rules{Owners: []string{"acme"}})
	e := r.entry(r.tenant, r.host+"/acme/*")
	if e == nil || e.Status() != scopedom.StatusPending {
		t.Fatalf("Strict, approver: %+v", e)
	}
	active, _ := r.scope.ListActiveTargets(context.Background(), r.tenant.String())
	for _, a := range active {
		if a.ID().Equals(e.ID()) {
			t.Fatal("an entry awaiting approval authorizes")
		}
	}
	if len(r.links(r.tenant, cfg.ID)) != 1 {
		t.Fatal("the pending entry is not linked")
	}
	noApprove := r.admin
	noApprove.ScopeApprove = false
	if _, err := r.svc.CreateTrustConfig(context.Background(), r.tenant, cirunapp.TrustConfigInput{
		Name: "writer", Provider: "gitlab", Issuer: r.idp.srv.URL, Rules: cirun.Rules{Owners: []string{"beta"}},
	}, noApprove); err != nil {
		t.Fatal(err)
	}
	if r.entry(r.tenant, r.host+"/beta/*") != nil {
		t.Fatal("Strict: a non-approver's trust added an entry")
	}
	if r.auditCount(r.tenant, "ci_trust_config.updated", r.host+"/beta/*") != 1 {
		t.Fatal("the refused pattern is not audited")
	}
}

// A pipeline run never creates an entry, and an entry a person deleted is
// not created again, by a run or a trust change.
func TestCITrustScope_RunsNeverCreate(t *testing.T) {
	r := newCIScopeRig(t)
	ctx := context.Background()
	// A trust saved before trusts managed scope, with manage_scope on but no
	// links: a run links an existing equal entry and creates nothing.
	now := time.Now().UTC()
	legacy := &cirun.TrustConfig{ID: shared.NewID(), TenantID: r.tenant, Name: "legacy", Provider: cirun.ProviderGitLab,
		Issuer: r.idp.srv.URL, Rules: cirun.Rules{Owners: []string{"acme", "beta"}}, Enabled: true, ManageScope: true,
		CreatedAt: now, UpdatedAt: now}
	legacy.Normalize()
	if err := r.repo.CreateTrustConfig(ctx, legacy); err != nil {
		t.Fatal(err)
	}
	manual, err := r.scope.CreateTarget(ctx, scopeapp.CreateTargetInput{TenantID: r.tenant.String(), TargetType: "repository",
		Pattern: r.host + "/beta/*"})
	if err != nil {
		t.Fatal(err)
	}
	if code, _ := r.exchange(r.tenant, r.idp.token(t, legacy.Audience, "acme/api", "main", strings.Repeat("1", 40), nil)); code != http.StatusCreated {
		t.Fatalf("exchange: %d", code)
	}
	if r.entry(r.tenant, r.host+"/acme/*") != nil {
		t.Fatal("a run created a scope entry")
	}
	links := r.links(r.tenant, legacy.ID)
	if len(links) != 1 || links[0].Pattern != r.host+"/beta/*" || !links[0].TargetID.Equals(manual.ID()) {
		t.Fatalf("links after the run: %+v", links)
	}

	// A person deletes the linked entry: neither a run nor a trust change
	// adds it again, and the link says so.
	if err := r.scope.DeleteTarget(ctx, manual.ID().String(), r.tenant.String()); err != nil {
		t.Fatal(err)
	}
	if code, _ := r.exchange(r.tenant, r.idp.token(t, legacy.Audience, "beta/api", "main", strings.Repeat("2", 40), nil)); code != http.StatusCreated {
		t.Fatalf("exchange: %d", code)
	}
	in := cirunapp.TrustConfigInput{Name: "legacy", Provider: "gitlab", Issuer: legacy.Issuer, Audience: legacy.Audience,
		Rules: cirun.Rules{Owners: []string{"acme", "beta"}}}
	if _, err := r.svc.UpdateTrustConfig(ctx, r.tenant, legacy.ID, in, r.admin); err != nil {
		t.Fatal(err)
	}
	if r.entry(r.tenant, r.host+"/beta/*") != nil {
		t.Fatal("a deleted entry came back")
	}
	for _, l := range r.links(r.tenant, legacy.ID) {
		if l.Pattern == r.host+"/beta/*" && (l.TargetID != nil || l.TargetRemovedAt == nil) {
			t.Fatalf("the removal is not recorded: %+v", l)
		}
	}
	// The administrator's change did add the namespace no one deleted.
	if r.entry(r.tenant, r.host+"/acme/*") == nil {
		t.Fatal("the trust change did not add acme")
	}
}

// A verified run puts a proof-waiting entry into effect only while the
// organization needs no approvals: if scan approval turned Strict after the
// trust was saved, the entry waits for its approvals instead.
func TestCITrustScope_ProofNeverBypassesStrict(t *testing.T) {
	r := newCIScopeRig(t)
	r.settings.set(r.tenant, tenant.ScopeSettings{CIScopeRequiresProof: true})
	cfg := r.scopeTrust(r.tenant, cirun.Rules{Owners: []string{"acme"}})
	pattern := r.host + "/acme/*"
	if e := r.entry(r.tenant, pattern); e == nil || e.Status() != scopedom.StatusInactive {
		t.Fatalf("before proof: %+v", e)
	}
	r.gov.set(scangov.ModeStrict)
	if code, _ := r.exchange(r.tenant, r.idp.token(t, cfg.Audience, "acme/api", "main", strings.Repeat("9", 40), nil)); code != http.StatusCreated {
		t.Fatalf("exchange: %d", code)
	}
	e := r.entry(r.tenant, pattern)
	if e == nil || e.Status() != scopedom.StatusPending || e.ApprovalsRequired() < 1 {
		t.Fatalf("proof under Strict: %+v", e)
	}
	active, _ := r.scope.ListActiveTargets(context.Background(), r.tenant.String())
	for _, a := range active {
		if a.ID().Equals(e.ID()) {
			t.Fatal("a proven entry authorizes without its approvals")
		}
	}
	// The evidence is still recorded.
	if l := r.links(r.tenant, cfg.ID); len(l) != 1 || l[0].SeenAt == nil {
		t.Fatalf("evidence: %+v", l)
	}
}

// The trust API's read: every trust's links in one read, and the evidence's
// repository and run only for a reader whose data scope reaches that
// repository (the time stays: it says a verified run happened).
func TestCITrustScope_ReadFollowsDataScope(t *testing.T) {
	r := newCIScopeRig(t)
	ctx := context.Background()
	a := r.scopeTrust(r.tenant, cirun.Rules{Owners: []string{"acme"}})
	b := r.scopeTrust(r.tenant, cirun.Rules{Owners: []string{"beta", "gamma"}})
	if code, _ := r.exchange(r.tenant, r.idp.token(t, a.Audience, "acme/api", "main", strings.Repeat("7", 40), nil)); code != http.StatusCreated {
		t.Fatalf("exchange: %d", code)
	}
	user, _ := shared.IDFromString(r.admin.UserID)
	read := func(scope *shared.DataScope) map[string][]scopedom.CITrustLink {
		t.Helper()
		m, err := r.svc.TrustScopes(ctx, r.tenant, nil, scope)
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	for name, scope := range map[string]*shared.DataScope{
		"unscoped":     nil,
		"unrestricted": {TenantID: r.tenant, UserID: user, Unrestricted: true},
	} {
		m := read(scope)
		if len(m[a.ID.String()]) != 1 || len(m[b.ID.String()]) != 2 {
			t.Fatalf("%s: grouping %v", name, m)
		}
		if l := m[a.ID.String()][0]; l.SeenAt == nil || l.SeenRepository != r.host+"/acme/api" || l.SeenRunID == nil {
			t.Fatalf("%s: evidence hidden: %+v", name, l)
		}
	}
	m := read(&shared.DataScope{TenantID: r.tenant, UserID: user}) // restricted, no access
	if l := m[a.ID.String()][0]; l.SeenAt == nil || l.SeenRepository != "" || l.SeenRunID != nil || l.SeenOwnerID != "" {
		t.Fatalf("restricted reader saw the evidence's repository: %+v", l)
	}
	// One trust only, and never another tenant's links.
	one, err := r.svc.TrustScopes(ctx, r.tenant, &b.ID, nil)
	if err != nil || len(one) != 1 || len(one[b.ID.String()]) != 2 {
		t.Fatalf("one trust: %v %v", one, err)
	}
	if other, err := r.svc.TrustScopes(ctx, r.other, nil, nil); err != nil || len(other) != 0 {
		t.Fatalf("another tenant read: %v %v", other, err)
	}
}
