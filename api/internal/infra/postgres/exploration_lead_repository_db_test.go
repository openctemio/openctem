package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/exploration"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// leadOn opens a takeover-check lead on asset in f's continuous exploration.
func leadOn(t *testing.T, repo *ExplorationRepository, f *coverageFixture, asset shared.ID) (*exploration.Lead, bool) {
	t.Helper()
	ctx := context.Background()
	ex, err := repo.EnsureContinuous(ctx, f.tenant)
	if err != nil {
		t.Fatal(err)
	}
	l, err := exploration.NewLead(exploration.NewLeadInput{
		TenantID: f.tenant, ExplorationID: ex, Type: "dns.takeover_check",
		Action: exploration.Action{Capability: "check.takeover"}, SubjectAssetID: &asset,
		ReasonCode: "cname_dangling", Origin: exploration.OriginRule, OriginRef: "dns.takeover_check@1", AutoActive: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	created, err := repo.OpenLead(ctx, l, []exploration.Link{{EndKind: exploration.EndAsset, EndID: &asset}})
	if err != nil {
		t.Fatalf("open lead: %v", err)
	}
	return l, created
}

func TestExplorationRepository_LeadLifecycle_DB(t *testing.T) {
	f := newCoverageFixture(t)
	repo := NewExplorationRepository(&DB{DB: f.db})
	ctx := context.Background()

	ex1, err := repo.EnsureContinuous(ctx, f.tenant)
	if err != nil {
		t.Fatal(err)
	}
	ex2, _ := repo.EnsureContinuous(ctx, f.tenant)
	if ex1 != ex2 {
		t.Fatal("one continuous exploration per tenant")
	}

	l, created := leadOn(t, repo, f, f.host)
	if !created || l.State != exploration.StateOpen {
		t.Fatalf("created=%v state=%s", created, l.State)
	}
	// The same question while the first is live: nothing is written.
	if _, again := leadOn(t, repo, f, f.host); again {
		t.Fatal("a second live lead with the same dedup key was stored")
	}

	got, err := repo.GetLead(ctx, f.tenant, l.ID, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.ActionHash != l.ActionHash || got.Tier != l.Tier || *got.SubjectAssetID != f.host {
		t.Fatalf("read back %+v", got)
	}
	links, err := repo.Links(ctx, f.tenant, l.ID)
	if err != nil || len(links) != 1 || links[0].Rel != exploration.RelDerivedFrom {
		t.Fatalf("links %v %v", links, err)
	}

	// Compare and set: a stale copy cannot overwrite.
	stale := *got
	if err := got.Move(exploration.StateRunning, got.UpdatedAt); err != nil {
		t.Fatal(err)
	}
	if err := repo.SaveLead(ctx, got); err != nil {
		t.Fatal(err)
	}
	if err := stale.Move(exploration.StateDismissed, stale.UpdatedAt); err != nil {
		t.Fatal(err)
	}
	if err := repo.SaveLead(ctx, &stale); !errors.Is(err, exploration.ErrStale) {
		t.Fatalf("stale save: %v", err)
	}

	// Dispatch link: the same run is recorded once.
	runRow := shared.NewID()
	f.exec(t, `INSERT INTO scan_runs (id, tenant_id, scan_id, status, trigger_type, kind) VALUES ($1, $2, $3, 'completed', 'system', 'system')`, runRow, f.tenant, f.scan)
	dl := exploration.Link{TenantID: f.tenant, LeadID: l.ID, Rel: exploration.RelDispatchedAs, EndKind: exploration.EndScanRun, EndID: &runRow}
	if n, err := repo.AddLinks(ctx, []exploration.Link{dl, dl}); err != nil || n != 1 {
		t.Fatalf("dispatch link added %d (%v), want 1", n, err)
	}

	// Closed: the question may be asked again.
	if err := got.Move(exploration.StateRefuted, got.UpdatedAt); err != nil {
		t.Fatal(err)
	}
	if err := repo.SaveLead(ctx, got); err != nil {
		t.Fatal(err)
	}
	if _, again := leadOn(t, repo, f, f.host); !again {
		t.Fatal("a closed lead must not hold the dedup key")
	}
}

// Every end of every row is tenant-bound by the database: another tenant's
// asset, finding, run or lead cannot be referenced, whatever the caller did.
func TestExplorationRepository_CrossTenantRefused_DB(t *testing.T) {
	f := newCoverageFixture(t)
	other := newCoverageFixture(t)
	repo := NewExplorationRepository(&DB{DB: f.db})
	ctx := context.Background()

	// A lead whose subject is another tenant's asset.
	ex, _ := repo.EnsureContinuous(ctx, f.tenant)
	foreign := other.host
	l, err := exploration.NewLead(exploration.NewLeadInput{
		TenantID: f.tenant, ExplorationID: ex, Type: "dns.takeover_check",
		Action: exploration.Action{Capability: "check.takeover"}, SubjectAssetID: &foreign,
		ReasonCode: "cname_dangling", Origin: exploration.OriginRule, OriginRef: "r@1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.OpenLead(ctx, l, nil); err == nil || !strings.Contains(err.Error(), "foreign key") {
		t.Fatalf("lead on another tenant's asset: %v", err)
	}
	// A lead in another tenant's exploration.
	otherEx, _ := repo.EnsureContinuous(ctx, other.tenant)
	host := f.host
	l2, _ := exploration.NewLead(exploration.NewLeadInput{
		TenantID: f.tenant, ExplorationID: otherEx, Type: "dns.takeover_check",
		Action: exploration.Action{Capability: "check.takeover"}, SubjectAssetID: &host,
		ReasonCode: "cname_dangling", Origin: exploration.OriginRule, OriginRef: "r@1",
	})
	if _, err := repo.OpenLead(ctx, l2, nil); err == nil {
		t.Fatal("a lead in another tenant's exploration was stored")
	}

	mine, _ := leadOn(t, repo, f, f.host)
	theirs, _ := leadOn(t, repo, other, other.host)
	theirFinding := other.finding(t, other.host, "nuclei", "", nil)
	theirRun := shared.NewID()
	other.exec(t, `INSERT INTO scan_runs (id, tenant_id, scan_id, status, trigger_type, kind) VALUES ($1, $2, $3, 'completed', 'system', 'system')`, theirRun, other.tenant, other.scan)
	for name, k := range map[string]exploration.Link{
		"asset":   {EndKind: exploration.EndAsset, EndID: &other.host},
		"finding": {EndKind: exploration.EndFinding, EndID: &theirFinding},
		"run":     {EndKind: exploration.EndScanRun, EndID: &theirRun},
		"lead":    {EndKind: exploration.EndLead, EndID: &theirs.ID},
	} {
		k.TenantID, k.LeadID, k.Rel = f.tenant, mine.ID, exploration.RelYields
		if _, err := repo.AddLinks(ctx, []exploration.Link{k}); err == nil {
			t.Errorf("link to another tenant's %s was stored", name)
		}
	}
	// A verdict on another tenant's lead under this tenant.
	if err := repo.AddVerdict(ctx, exploration.Verdict{TenantID: f.tenant, LeadID: theirs.ID,
		Verdict: exploration.VerdictRefuted, Tier: exploration.TierDeterministic, Checker: "scan_run"}); err == nil {
		t.Fatal("a verdict on another tenant's lead was stored")
	}
	// Reads are tenant-bound: another tenant's id is not found.
	if _, err := repo.GetLead(ctx, f.tenant, theirs.ID, nil); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("read of another tenant's lead: %v", err)
	}
	list, err := repo.ListLeads(ctx, f.tenant, exploration.LeadFilter{})
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range list {
		if l.TenantID != f.tenant {
			t.Fatalf("list returned tenant %s", l.TenantID)
		}
	}
	if links, _ := repo.Links(ctx, f.tenant, theirs.ID); len(links) != 0 {
		t.Fatal("links of another tenant's lead were read")
	}
}

// A restricted reader sees only leads on assets in their data scope; a
// member with no scope row sees none.
func TestExplorationRepository_DataScope_DB(t *testing.T) {
	f := newCoverageFixture(t)
	repo := NewExplorationRepository(&DB{DB: f.db})
	ctx := context.Background()
	inScope, _ := leadOn(t, repo, f, f.host)
	outOfScope, _ := leadOn(t, repo, f, f.otherHost)
	member := f.user(t)
	f.exec(t, `INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id) VALUES ($1, $2, $3)`, member, f.tenant, f.host)
	scope := &shared.DataScope{TenantID: f.tenant, UserID: member}

	list, err := repo.ListLeads(ctx, f.tenant, exploration.LeadFilter{Scope: scope})
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].ID != inScope.ID {
		t.Fatalf("scoped list = %d leads", len(list))
	}
	if _, err := repo.GetLead(ctx, f.tenant, outOfScope.ID, scope); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("out-of-scope lead read: %v", err)
	}
	nobody := &shared.DataScope{TenantID: f.tenant, UserID: f.user(t)}
	if list, _ := repo.ListLeads(ctx, f.tenant, exploration.LeadFilter{Scope: nobody}); len(list) != 0 {
		t.Fatalf("member with no scope row saw %d leads", len(list))
	}
}

// Verdicts are append-only for the application role: no edit, no delete;
// they go only with their lead (and a deleted account is cleared).
func TestExplorationRepository_VerdictsAppendOnly_DB(t *testing.T) {
	f := newCoverageFixture(t)
	repo := NewExplorationRepository(&DB{DB: f.db})
	ctx := context.Background()
	l, _ := leadOn(t, repo, f, f.host)
	user := f.user(t)
	v := exploration.Verdict{ID: shared.NewID(), TenantID: f.tenant, LeadID: l.ID, Verdict: exploration.VerdictRefuted,
		Tier: exploration.TierHuman, Checker: "user:" + user.String(), DecidedBy: &user, Reason: "checked by hand"}
	if err := repo.AddVerdict(ctx, v); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.ExecContext(ctx, `UPDATE exploration_verdicts SET verdict = 'proven' WHERE tenant_id = $1 AND id = $2`,
		f.tenant.String(), v.ID.String()); err == nil || !strings.Contains(err.Error(), "append-only") {
		t.Fatalf("verdict edit: %v", err)
	}
	if _, err := f.db.ExecContext(ctx, `DELETE FROM exploration_verdicts WHERE tenant_id = $1 AND id = $2`,
		f.tenant.String(), v.ID.String()); err == nil || !strings.Contains(err.Error(), "append-only") {
		t.Fatalf("verdict delete: %v", err)
	}
	// Proof wording holds at the repository too.
	if err := repo.AddVerdict(ctx, exploration.Verdict{TenantID: f.tenant, LeadID: l.ID, Verdict: exploration.VerdictProven,
		Tier: exploration.TierAI, Checker: "ai"}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("AI proof: %v", err)
	}
	// Deleting the account clears decided_by and keeps the verdict.
	f.exec(t, `DELETE FROM users WHERE id = $1`, user)
	vs, err := repo.Verdicts(ctx, f.tenant, l.ID)
	if err != nil || len(vs) != 1 || vs[0].DecidedBy != nil {
		t.Fatalf("verdicts after account deletion: %+v %v", vs, err)
	}
}
