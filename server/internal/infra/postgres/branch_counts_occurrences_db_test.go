package postgres

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// Branch counters and branch compare read the occurrence model
// (migration branch_counts_from_occurrences, RFC-144 §4): a finding present on
// main and on a feature branch counts on both, a finding fixed on the feature
// branch counts only on main, and a row from before occurrences counts on its
// findings.branch_id. Occurrences are read within the branch's tenant only.

type branchCountsFixture struct {
	db            *DB
	tenant, other shared.ID
	repo          shared.ID
	main, feature shared.ID
}

func newBranchCountsFixture(ctx context.Context, t *testing.T) *branchCountsFixture {
	t.Helper()
	raw := openGroupsDB(t)
	f := &branchCountsFixture{db: &DB{DB: raw}, tenant: seedTestTenant(ctx, t, raw), other: seedTestTenant(ctx, t, raw),
		repo: shared.NewID(), main: shared.NewID(), feature: shared.NewID()}
	f.exec(ctx, t, `INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, $3, 'repository')`,
		f.repo.String(), f.tenant.String(), "repo-"+f.repo.String())
	f.exec(ctx, t, `INSERT INTO asset_repositories (asset_id) VALUES ($1)`, f.repo.String())
	f.exec(ctx, t, `INSERT INTO repository_branches (id, repository_id, name, branch_type, is_default) VALUES
		($1, $3, 'main', 'main', true), ($2, $3, 'feature/pay', 'feature', false)`,
		f.main.String(), f.feature.String(), f.repo.String())
	return f
}

func (f *branchCountsFixture) exec(ctx context.Context, t *testing.T, q string, args ...any) {
	t.Helper()
	if _, err := f.db.ExecContext(ctx, q, args...); err != nil {
		t.Fatalf("%v\n%s", err, q)
	}
}

// finding inserts an open high finding of tenant on the repository asset with
// the given headline branch.
func (f *branchCountsFixture) finding(ctx context.Context, t *testing.T, tenant shared.ID, headline shared.ID, fp string) shared.ID {
	t.Helper()
	id := shared.NewID()
	f.exec(ctx, t, `INSERT INTO findings (id, tenant_id, asset_id, branch_id, source, tool_name, message, title, severity, fingerprint, status)
		VALUES ($1, $2, $3, $4, 'sast', 'opengrep', 'm', $5, 'high', $5, 'new')`,
		id.String(), tenant.String(), f.repo.String(), headline.String(), fp)
	return id
}

func (f *branchCountsFixture) occurrence(ctx context.Context, t *testing.T, tenant, finding, branchID shared.ID, status string) {
	t.Helper()
	f.exec(ctx, t, `INSERT INTO finding_branch_occurrences (tenant_id, finding_id, branch_id, repository_id, status)
		VALUES ($1, $2, $3, $4, $5)`, tenant.String(), finding.String(), branchID.String(), f.repo.String(), status)
}

func (f *branchCountsFixture) total(ctx context.Context, t *testing.T, branchID shared.ID) int {
	t.Helper()
	var n int
	if err := f.db.QueryRowContext(ctx, `SELECT findings_total FROM repository_branches WHERE id = $1`, branchID.String()).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestBranchCounts_FromOccurrences(t *testing.T) {
	ctx := context.Background()
	f := newBranchCountsFixture(ctx, t)

	// sqli on both branches (headline main), xss only on the feature branch,
	// ssrf on main and fixed on the feature branch.
	sqli := f.finding(ctx, t, f.tenant, f.main, "fp-sqli")
	xss := f.finding(ctx, t, f.tenant, f.feature, "fp-xss")
	ssrf := f.finding(ctx, t, f.tenant, f.main, "fp-ssrf")
	f.occurrence(ctx, t, f.tenant, sqli, f.main, "open")
	f.occurrence(ctx, t, f.tenant, sqli, f.feature, "open")
	f.occurrence(ctx, t, f.tenant, xss, f.feature, "open")
	f.occurrence(ctx, t, f.tenant, ssrf, f.main, "open")
	f.occurrence(ctx, t, f.tenant, ssrf, f.feature, "auto_fixed")

	if got := f.total(ctx, t, f.main); got != 2 {
		t.Errorf("main: findings_total = %d, want 2 (sqli, ssrf)", got)
	}
	if got := f.total(ctx, t, f.feature); got != 2 {
		t.Errorf("feature/pay: findings_total = %d, want 2 (sqli, xss)", got)
	}

	// The feature branch stops seeing sqli: its occurrence is fixed there.
	f.exec(ctx, t, `UPDATE finding_branch_occurrences SET status = 'auto_fixed' WHERE finding_id = $1 AND branch_id = $2`,
		sqli.String(), f.feature.String())
	if got := f.total(ctx, t, f.feature); got != 1 {
		t.Errorf("feature/pay after the fix: findings_total = %d, want 1", got)
	}
	if got := f.total(ctx, t, f.main); got != 2 {
		t.Errorf("main after the feature fix: findings_total = %d, want 2", got)
	}

	// A status change of the finding moves every branch it is present on.
	f.exec(ctx, t, `UPDATE findings SET status = 'false_positive' WHERE id = $1`, xss.String())
	if got := f.total(ctx, t, f.feature); got != 0 {
		t.Errorf("feature/pay after the false positive: findings_total = %d, want 0", got)
	}

	// Deleting a finding removes it from every branch.
	f.exec(ctx, t, `DELETE FROM findings WHERE id = $1`, ssrf.String())
	if got := f.total(ctx, t, f.main); got != 1 {
		t.Errorf("main after delete: findings_total = %d, want 1", got)
	}
}

func TestBranchCounts_LegacyFindingWithoutOccurrences(t *testing.T) {
	ctx := context.Background()
	f := newBranchCountsFixture(ctx, t)
	f.finding(ctx, t, f.tenant, f.feature, "fp-legacy")
	if got := f.total(ctx, t, f.feature); got != 1 {
		t.Errorf("a finding with no occurrence counts on branch_id: findings_total = %d, want 1", got)
	}
}

func TestBranchCounts_OtherTenantOccurrenceIgnored(t *testing.T) {
	ctx := context.Background()
	f := newBranchCountsFixture(ctx, t)
	// A row of another tenant that names this tenant's branch must not move
	// its counters (it has an occurrence, so the legacy rule does not apply).
	otherRepo, foreign := shared.NewID(), shared.NewID()
	f.exec(ctx, t, `INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, $3, 'repository')`,
		otherRepo.String(), f.other.String(), "repo-"+otherRepo.String())
	f.exec(ctx, t, `INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, title, severity, fingerprint, status)
		VALUES ($1, $2, $3, 'sast', 'opengrep', 'm', 'fp-foreign', 'high', 'fp-foreign', 'new')`,
		foreign.String(), f.other.String(), otherRepo.String())
	f.exec(ctx, t, `INSERT INTO finding_branch_occurrences (tenant_id, finding_id, branch_id, repository_id, status)
		VALUES ($1, $2, $3, $4, 'open')`, f.other.String(), foreign.String(), f.feature.String(), otherRepo.String())
	if got := f.total(ctx, t, f.feature); got != 0 {
		t.Errorf("another tenant's occurrence counted: findings_total = %d, want 0", got)
	}
	cmp, err := NewBranchRepository(f.db).CompareBranches(ctx, f.tenant, f.repo, "main", "feature/pay")
	if err != nil {
		t.Fatal(err)
	}
	if cmp.NewFindings != 0 || len(cmp.NewItems) != 0 {
		t.Errorf("another tenant's finding in the compare: %+v", cmp)
	}
	// The other tenant cannot compare this tenant's repository.
	cmp, err = NewBranchRepository(f.db).CompareBranches(ctx, f.other, f.repo, "main", "feature/pay")
	if err != nil {
		t.Fatal(err)
	}
	if cmp.NewFindings != 0 || cmp.CommonFindings != 0 || cmp.ResolvedFindings != 0 {
		t.Errorf("cross-tenant compare returned data: %+v", cmp)
	}
}

func TestCompareBranches_ByOccurrenceState(t *testing.T) {
	ctx := context.Background()
	f := newBranchCountsFixture(ctx, t)
	sqli := f.finding(ctx, t, f.tenant, f.main, "fp-sqli")
	xss := f.finding(ctx, t, f.tenant, f.feature, "fp-xss")
	ssrf := f.finding(ctx, t, f.tenant, f.main, "fp-ssrf")
	f.occurrence(ctx, t, f.tenant, sqli, f.main, "open")
	f.occurrence(ctx, t, f.tenant, sqli, f.feature, "open")
	f.occurrence(ctx, t, f.tenant, xss, f.feature, "open")
	f.occurrence(ctx, t, f.tenant, ssrf, f.main, "open")
	f.occurrence(ctx, t, f.tenant, ssrf, f.feature, "auto_fixed")

	cmp, err := NewBranchRepository(f.db).CompareBranches(ctx, f.tenant, f.repo, "main", "feature/pay")
	if err != nil {
		t.Fatal(err)
	}
	if cmp.NewFindings != 1 || cmp.ResolvedFindings != 1 || cmp.CommonFindings != 1 {
		t.Fatalf("compare main -> feature/pay = new %d, resolved %d, common %d; want 1, 1, 1",
			cmp.NewFindings, cmp.ResolvedFindings, cmp.CommonFindings)
	}
	if len(cmp.NewItems) != 1 || cmp.NewItems[0].ID != xss.String() {
		t.Errorf("new items = %+v, want only xss", cmp.NewItems)
	}
	if cmp.NewBySeverity["high"] != 1 {
		t.Errorf("new by severity = %v, want high: 1", cmp.NewBySeverity)
	}
}
