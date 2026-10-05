package postgres

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/filterspec"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// Branch-only findings (docs/architecture/branch-only-findings.md, migration
// 001132): marked on insert when first seen on a branch that does not count,
// promoted when a counting branch sees them, left out of the default list,
// expired when no branch still shows them. Every write is tenant-scoped.

type branchOnlyFixture struct {
	db                       *sql.DB
	tenant, repo             shared.ID
	main, feature, release   shared.ID
	noDefaultRepo, orphanTop shared.ID
}

func newBranchOnlyFixture(ctx context.Context, t *testing.T) *branchOnlyFixture {
	t.Helper()
	db := openGroupsDB(t)
	f := &branchOnlyFixture{db: db, tenant: seedTestTenant(ctx, t, db),
		repo: shared.NewID(), main: shared.NewID(), feature: shared.NewID(), release: shared.NewID(),
		noDefaultRepo: shared.NewID(), orphanTop: shared.NewID()}
	f.repoAsset(ctx, t, f.tenant, f.repo)
	f.branch(ctx, t, f.main, f.repo, "main", "main", true)
	f.branch(ctx, t, f.feature, f.repo, "feature/x", "feature", false)
	f.branch(ctx, t, f.release, f.repo, "release/1", "release", false)
	// A repository with no known default branch: nothing on it is hidden.
	f.repoAsset(ctx, t, f.tenant, f.noDefaultRepo)
	f.branch(ctx, t, f.orphanTop, f.noDefaultRepo, "feature/y", "feature", false)
	return f
}

func (f *branchOnlyFixture) repoAsset(ctx context.Context, t *testing.T, tenant, id shared.ID) {
	t.Helper()
	f.exec(ctx, t, `INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, $3, 'repository')`,
		id.String(), tenant.String(), "repo-"+id.String())
	f.exec(ctx, t, `INSERT INTO asset_repositories (asset_id) VALUES ($1)`, id.String())
}

func (f *branchOnlyFixture) branch(ctx context.Context, t *testing.T, id, repo shared.ID, name, typ string, def bool) {
	t.Helper()
	f.exec(ctx, t, `INSERT INTO repository_branches (id, repository_id, name, branch_type, is_default) VALUES ($1, $2, $3, $4, $5)`,
		id.String(), repo.String(), name, typ, def)
}

func (f *branchOnlyFixture) exec(ctx context.Context, t *testing.T, q string, args ...any) {
	t.Helper()
	if _, err := f.db.ExecContext(ctx, q, args...); err != nil {
		t.Fatalf("fixture: %v\n%s", err, q)
	}
}

// finding inserts a new finding of tenant on asset, on branch (nil = none),
// with a 30-day SLA from a detection 10 days ago, and its occurrence on that
// branch.
func (f *branchOnlyFixture) finding(ctx context.Context, t *testing.T, tenant, asset shared.ID, branch *shared.ID) (shared.ID, string) {
	t.Helper()
	id := shared.NewID()
	fp := "fp-" + id.String()
	var b any
	if branch != nil {
		b = branch.String()
	}
	f.exec(ctx, t, `INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status,
			branch_id, first_detected_at, sla_deadline, sla_status)
		VALUES ($1, $2, $3, 'sast', 'semgrep', 'm', 'high', $4, 'new', $5,
			NOW() - interval '10 days', NOW() + interval '20 days', 'on_track')`,
		id.String(), tenant.String(), asset.String(), fp, b)
	if branch != nil {
		f.exec(ctx, t, `INSERT INTO finding_branch_occurrences (tenant_id, finding_id, branch_id, repository_id)
			VALUES ($1, $2, $3, $4)`, tenant.String(), id.String(), branch.String(), asset.String())
	}
	return id, fp
}

func (f *branchOnlyFixture) branchOnly(ctx context.Context, t *testing.T, id shared.ID) bool {
	t.Helper()
	var v bool
	if err := f.db.QueryRowContext(ctx, `SELECT branch_only FROM findings WHERE id = $1`, id.String()).Scan(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestBranchOnly_MarkedOnInsertByBranch(t *testing.T) {
	ctx := context.Background()
	f := newBranchOnlyFixture(ctx, t)

	onFeature, _ := f.finding(ctx, t, f.tenant, f.repo, &f.feature)
	onMain, _ := f.finding(ctx, t, f.tenant, f.repo, &f.main)
	onRelease, _ := f.finding(ctx, t, f.tenant, f.repo, &f.release)
	noBranch, _ := f.finding(ctx, t, f.tenant, f.repo, nil)
	noDefault, _ := f.finding(ctx, t, f.tenant, f.noDefaultRepo, &f.orphanTop)

	if !f.branchOnly(ctx, t, onFeature) {
		t.Fatal("a finding first seen on a feature branch is branch-only")
	}
	for name, id := range map[string]shared.ID{"default branch": onMain, "release branch": onRelease,
		"no branch": noBranch, "repository without a default branch": noDefault} {
		if f.branchOnly(ctx, t, id) {
			t.Fatalf("finding on %s must count", name)
		}
	}

	// A protected branch counts.
	f.exec(ctx, t, `UPDATE repository_branches SET is_protected = TRUE WHERE id = $1`, f.release.String())
	prot := shared.NewID()
	f.branch(ctx, t, prot, f.repo, "stable", "other", false)
	f.exec(ctx, t, `UPDATE repository_branches SET is_protected = TRUE WHERE id = $1`, prot.String())
	onProtected, _ := f.finding(ctx, t, f.tenant, f.repo, &prot)
	if f.branchOnly(ctx, t, onProtected) {
		t.Fatal("finding on a protected branch must count")
	}
}

func TestBranchOnly_PromotedWhenACountingBranchSeesIt(t *testing.T) {
	ctx := context.Background()
	f := newBranchOnlyFixture(ctx, t)
	repo := NewFindingRepository(&DB{DB: f.db})

	id, fp := f.finding(ctx, t, f.tenant, f.repo, &f.feature)
	stay, stayFP := f.finding(ctx, t, f.tenant, f.repo, &f.feature)

	// Still only on the feature branch: nothing to promote.
	if got, err := repo.PromoteBranchOnlyByFingerprints(ctx, f.tenant, []string{fp, stayFP}); err != nil || len(got) != 0 {
		t.Fatalf("promoted %v (%v) before any counting sighting", got, err)
	}

	// The default branch sees it.
	if err := repo.UpsertBranchOccurrences(ctx, f.tenant, []vulnerability.BranchOccurrenceUpsert{
		{Fingerprint: fp, BranchID: f.main, ScanID: "s1"},
	}); err != nil {
		t.Fatal(err)
	}

	// Another tenant promoting the same fingerprints changes nothing.
	other := seedTestTenant(ctx, t, f.db)
	if got, err := repo.PromoteBranchOnlyByFingerprints(ctx, other, []string{fp}); err != nil || len(got) != 0 {
		t.Fatalf("cross-tenant promote = %v (%v)", got, err)
	}
	if !f.branchOnly(ctx, t, id) {
		t.Fatal("cross-tenant promote cleared the mark")
	}

	got, err := repo.PromoteBranchOnlyByFingerprints(ctx, f.tenant, []string{fp, stayFP})
	if err != nil || len(got) != 1 || got[0] != id {
		t.Fatalf("promoted %v (%v), want only %s", got, err, id)
	}
	if f.branchOnly(ctx, t, id) || !f.branchOnly(ctx, t, stay) {
		t.Fatal("only the finding the default branch saw is promoted")
	}

	// The SLA clock starts now: the deadline keeps its 30-day length from
	// promotion. first_detected_at keeps the first sighting (10 days ago).
	var firstDetected, deadline time.Time
	var slaStatus string
	if err := f.db.QueryRowContext(ctx, `SELECT first_detected_at, sla_deadline, sla_status FROM findings WHERE id = $1`, id.String()).
		Scan(&firstDetected, &deadline, &slaStatus); err != nil {
		t.Fatal(err)
	}
	if age := time.Since(firstDetected); age < 9*24*time.Hour {
		t.Fatalf("first_detected_at moved (%v ago), want the first sighting", age)
	}
	if d := time.Until(deadline); d < 30*24*time.Hour-time.Minute || d > 30*24*time.Hour+time.Minute {
		t.Fatalf("SLA deadline in %v, want 30 days from promotion", d)
	}
	if slaStatus != "on_track" {
		t.Fatalf("sla_status %s", slaStatus)
	}

	marked, err := repo.BranchOnlyIDs(ctx, f.tenant, []shared.ID{id, stay})
	if err != nil || marked[id] || !marked[stay] {
		t.Fatalf("BranchOnlyIDs = %v (%v)", marked, err)
	}
	if marked, err := repo.BranchOnlyIDs(ctx, other, []shared.ID{stay}); err != nil || len(marked) != 0 {
		t.Fatalf("BranchOnlyIDs across tenants = %v (%v)", marked, err)
	}
}

func TestBranchOnly_PromotedWhenItsBranchStartsToCount(t *testing.T) {
	ctx := context.Background()
	f := newBranchOnlyFixture(ctx, t)
	id, _ := f.finding(ctx, t, f.tenant, f.repo, &f.feature)

	f.exec(ctx, t, `UPDATE repository_branches SET scan_on_push = FALSE WHERE id = $1`, f.feature.String())
	if !f.branchOnly(ctx, t, id) {
		t.Fatal("an unrelated branch update promoted the finding")
	}
	f.exec(ctx, t, `UPDATE repository_branches SET is_protected = TRUE WHERE id = $1`, f.feature.String())
	if f.branchOnly(ctx, t, id) {
		t.Fatal("protecting the branch must promote its branch-only findings")
	}
}

func TestBranchOnly_DefaultListLeavesThemOut(t *testing.T) {
	ctx := context.Background()
	f := newBranchOnlyFixture(ctx, t)
	repo := NewFindingRepository(&DB{DB: f.db})
	branchOnly, _ := f.finding(ctx, t, f.tenant, f.repo, &f.feature)
	counting, _ := f.finding(ctx, t, f.tenant, f.repo, &f.main)

	actor, err := filterspec.UserActor(filterspec.UserActorInput{TenantID: f.tenant, IsAdmin: true})
	if err != nil {
		t.Fatal(err)
	}
	list := func(spec *filterspec.Spec) map[shared.ID]bool {
		t.Helper()
		w, err := filterspec.Compile(vulnerability.WithBranchOnlyDefault(spec), vulnerability.FindingFields, actor)
		if err != nil {
			t.Fatal(err)
		}
		res, err := repo.ListWhere(ctx, w, pagination.New(1, 50))
		if err != nil {
			t.Fatal(err)
		}
		out := map[shared.ID]bool{}
		for _, fd := range res.Data {
			out[fd.ID()] = fd.BranchOnly()
		}
		return out
	}
	leaf := func(field string, v any) *filterspec.Spec {
		return &filterspec.Spec{Root: &filterspec.Node{Leaf: &filterspec.Leaf{Field: field, Op: filterspec.OpEq, Values: []any{v}}}}
	}

	got := list(&filterspec.Spec{})
	if _, ok := got[branchOnly]; ok || len(got) != 1 {
		t.Fatalf("default list = %v, want only the counting finding", got)
	}
	got = list(leaf("branch_only", true))
	if mark, ok := got[branchOnly]; !ok || !mark || len(got) != 1 {
		t.Fatalf("branch_only=true list = %v", got)
	}
	branchSpec := &filterspec.Spec{Root: &filterspec.Node{Leaf: &filterspec.Leaf{Field: "branch_id", Op: filterspec.OpIn, Values: []any{f.feature.String()}}}}
	if got = list(branchSpec); !got[branchOnly] {
		t.Fatalf("a branch filter shows the branch's findings: %v", got)
	}
	if _, ok := list(&filterspec.Spec{})[counting]; !ok {
		t.Fatal("the counting finding is listed")
	}
}

func TestBranchOnly_ExpiredWhenNoBranchShowsIt(t *testing.T) {
	ctx := context.Background()
	f := newBranchOnlyFixture(ctx, t)
	repo := NewFindingRepository(&DB{DB: f.db})

	gone, _ := f.finding(ctx, t, f.tenant, f.repo, &f.feature)
	live, _ := f.finding(ctx, t, f.tenant, f.repo, &f.feature)
	recent, _ := f.finding(ctx, t, f.tenant, f.repo, &f.feature)
	counting, _ := f.finding(ctx, t, f.tenant, f.repo, &f.main)
	// gone: its feature-branch occurrence was last seen 40 days ago (the
	// branch merged and is no longer scanned). live: seen there yesterday.
	// recent: the occurrence is stale but the finding was seen this week.
	f.exec(ctx, t, `UPDATE findings SET last_seen_at = NOW() - interval '40 days' WHERE id = ANY($1::uuid[])`,
		"{"+gone.String()+","+live.String()+","+counting.String()+"}")
	f.exec(ctx, t, `UPDATE finding_branch_occurrences SET last_seen_at = NOW() - interval '40 days' WHERE finding_id = ANY($1::uuid[])`,
		"{"+gone.String()+","+recent.String()+","+counting.String()+"}")
	f.exec(ctx, t, `UPDATE finding_branch_occurrences SET last_seen_at = NOW() - interval '1 day' WHERE finding_id = $1`, live.String())
	// The feature branch keeps findings while inactive (the default): that
	// does not keep a branch-only finding alive.
	f.exec(ctx, t, `UPDATE repository_branches SET keep_when_inactive = TRUE WHERE repository_id = $1`, f.repo.String())

	other := seedTestTenant(ctx, t, f.db)
	if n, err := repo.ExpireFeatureBranchFindings(ctx, other, 30); err != nil || n != 0 {
		t.Fatalf("another tenant's expiry changed %d rows (%v)", n, err)
	}

	n, err := repo.ExpireFeatureBranchFindings(ctx, f.tenant, 30)
	if err != nil || n != 1 {
		t.Fatalf("expired %d (%v), want 1", n, err)
	}
	if st, at, _ := findingStatus(ctx, t, f.db, gone); st != "not_observed" || at.Valid {
		t.Fatalf("gone: status %s resolved_at %v, want not_observed, never resolved", st, at)
	}
	for _, id := range []shared.ID{live, recent, counting} {
		if st, _, _ := findingStatus(ctx, t, f.db, id); st != "new" {
			t.Fatalf("finding %s moved to %s", id, st)
		}
	}
	var acts int
	if err := f.db.QueryRowContext(ctx, `SELECT count(*) FROM finding_activities
		WHERE tenant_id = $1 AND finding_id = $2 AND activity_type = 'status_changed'
		  AND changes->>'reason' = 'branch_only_expired' AND changes->>'old_status' = 'new'`,
		f.tenant.String(), gone.String()).Scan(&acts); err != nil || acts != 1 {
		t.Fatalf("expiry activity rows = %d (%v), want 1", acts, err)
	}

	// A deleted branch takes its occurrences: the finding expires once unseen.
	f.exec(ctx, t, `UPDATE findings SET last_seen_at = NOW() - interval '40 days' WHERE id = $1`, live.String())
	f.exec(ctx, t, `DELETE FROM repository_branches WHERE id = $1`, f.feature.String())
	if n, err := repo.ExpireFeatureBranchFindings(ctx, f.tenant, 30); err != nil || n != 1 {
		t.Fatalf("after branch delete expired %d (%v), want 1", n, err)
	}
}
