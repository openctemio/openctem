package postgres

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/ingestreport"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// A leaked secret is not fixed because a scan stopped reporting it: removing
// it from the branch does not revoke it. Both auto-resolve paths leave it
// open, mark it stale (not observed) and write a timeline entry; the same scan
// still resolves an ordinary finding.

func (f *coverageFixture) secret(t *testing.T, asset shared.ID, scanID string, branch *shared.ID, byType bool) shared.ID {
	t.Helper()
	id := f.finding(t, asset, "nuclei", scanID, branch)
	if byType {
		f.exec(t, `UPDATE findings SET finding_type = 'secret' WHERE id = $1`, id)
	} else {
		f.exec(t, `UPDATE findings SET source = 'secret' WHERE id = $1`, id)
	}
	return id
}

func (f *coverageFixture) observation(t *testing.T, id shared.ID) (status, observation string, activities int) {
	t.Helper()
	if err := f.db.QueryRowContext(context.Background(),
		`SELECT status, observation_state FROM findings WHERE id = $1`, id.String()).Scan(&status, &observation); err != nil {
		t.Fatalf("observation: %v", err)
	}
	if err := f.db.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM finding_activities WHERE finding_id = $1 AND source = 'secret_not_observed'`, id.String()).Scan(&activities); err != nil {
		t.Fatalf("activities: %v", err)
	}
	return status, observation, activities
}

func TestSecretNotAutoResolved_NonRepositoryCoverage(t *testing.T) {
	f := newCoverageFixture(t)
	ctx := context.Background()
	repo := NewFindingRepository(&DB{DB: f.db})

	_, earlier := f.run(t, f.scan, "completed", f.host)
	plain := f.finding(t, f.host, "nuclei", earlier, nil)
	secretType := f.secret(t, f.host, earlier, nil, true)
	secretSource := f.secret(t, f.host, earlier, nil, false)
	_, today := f.run(t, f.scan, "completed", f.host)
	q := ingestreport.CoverageQuery{AssetIDs: []shared.ID{f.host}, ToolName: "nuclei", ProfileID: f.profile.String(), SeenScanIDs: []string{today}}

	stale, open, err := repo.CoverageStaleFindings(ctx, f.tenant, q)
	if err != nil {
		t.Fatal(err)
	}
	if got := idStrings(stale); len(got) != 1 || got[0] != plain.String() {
		t.Fatalf("stale candidates = %v, want only the ordinary finding", got)
	}
	if open != 1 {
		t.Fatalf("open = %d, want 1 (secrets are not part of the blinding guard)", open)
	}
	// Defense in depth: even handed the ids, the resolve closes no secret.
	resolved, err := repo.ResolveCoverageStale(ctx, f.tenant, []shared.ID{plain, secretType, secretSource})
	if err != nil || len(resolved) != 1 || resolved[0] != plain {
		t.Fatalf("resolve = %v, %v; want only the ordinary finding", resolved, err)
	}
	for name, id := range map[string]shared.ID{"by type": secretType, "by source": secretSource} {
		if st, obs, _ := f.observation(t, id); st != "new" || obs != "present" {
			t.Fatalf("secret %s after resolve: status=%s observation=%s, want new/present", name, st, obs)
		}
	}

	// Another tenant's call marks and resolves nothing of this tenant.
	other := seedTestTenant(ctx, t, f.db)
	if got, err := repo.MarkCoverageSecretsNotObserved(ctx, other, q); err != nil || len(got) != 0 {
		t.Fatalf("cross-tenant mark = %v, %v", got, err)
	}
	if got, err := repo.markSecretsNotObserved(ctx, other, []shared.ID{secretType}, "x", "x", false); err != nil || len(got) != 0 {
		t.Fatalf("cross-tenant mark by id = %v, %v", got, err)
	}

	marked, err := repo.MarkCoverageSecretsNotObserved(ctx, f.tenant, q)
	if err != nil || len(marked) != 2 {
		t.Fatalf("mark = %v, %v; want both secrets", marked, err)
	}
	for name, id := range map[string]shared.ID{"by type": secretType, "by source": secretSource} {
		if st, obs, n := f.observation(t, id); st != "new" || obs != "stale" || n != 1 {
			t.Fatalf("secret %s: status=%s observation=%s activities=%d, want new/stale/1", name, st, obs, n)
		}
	}
	if st, obs, _ := f.observation(t, plain); st != "resolved" || obs != "present" {
		t.Fatalf("ordinary finding: status=%s observation=%s", st, obs)
	}
	// Marking again writes no second entry.
	if again, err := repo.MarkCoverageSecretsNotObserved(ctx, f.tenant, q); err != nil || len(again) != 0 {
		t.Fatalf("second mark = %v, %v", again, err)
	}
	if _, _, n := f.observation(t, secretType); n != 1 {
		t.Fatalf("activities after second mark = %d, want 1", n)
	}
}

func TestSecretNotAutoResolved_DefaultBranchScan(t *testing.T) {
	f := newCoverageFixture(t)
	ctx := context.Background()
	repo := NewFindingRepository(&DB{DB: f.db})

	f.exec(t, `INSERT INTO asset_repositories (asset_id) VALUES ($1)`, f.repoAsset)
	branch, feature := shared.NewID(), shared.NewID()
	f.exec(t, `INSERT INTO repository_branches (id, repository_id, name, is_default) VALUES ($1, $2, 'main', true)`, branch, f.repoAsset)
	f.exec(t, `INSERT INTO repository_branches (id, repository_id, name, is_default) VALUES ($1, $2, 'dev', false)`, feature, f.repoAsset)

	_, earlier := f.run(t, f.scan, "completed", f.repoAsset)
	plain := f.finding(t, f.repoAsset, "nuclei", earlier, &branch)
	secretType := f.secret(t, f.repoAsset, earlier, &branch, true)
	secretSource := f.secret(t, f.repoAsset, earlier, &branch, false)
	secretFeature := f.secret(t, f.repoAsset, earlier, &feature, true) // not on the default branch: untouched
	_, today := f.run(t, f.scan, "completed", f.repoAsset)
	q := ingestreport.CoverageQuery{AssetIDs: []shared.ID{f.repoAsset}, ToolName: "nuclei", ProfileID: f.profile.String(), SeenScanIDs: []string{today}}

	stale, open, err := repo.RepoCoverageStaleFindings(ctx, f.tenant, q)
	if err != nil {
		t.Fatal(err)
	}
	if got := idStrings(stale); len(got) != 1 || got[0] != plain.String() || open != 1 {
		t.Fatalf("stale = %v open = %d, want only the ordinary finding and 1", got, open)
	}
	resolved, err := repo.ResolveRepoCoverageStale(ctx, f.tenant, []shared.ID{plain, secretType, secretSource})
	if err != nil || len(resolved) != 1 || resolved[0] != plain {
		t.Fatalf("resolve = %v, %v; want only the ordinary finding", resolved, err)
	}
	if got, err := repo.MarkRepoCoverageSecretsNotObserved(ctx, seedTestTenant(ctx, t, f.db), q); err != nil || len(got) != 0 {
		t.Fatalf("cross-tenant mark = %v, %v", got, err)
	}
	marked, err := repo.MarkRepoCoverageSecretsNotObserved(ctx, f.tenant, q)
	if err != nil || len(marked) != 2 {
		t.Fatalf("mark = %v, %v; want the two default-branch secrets", marked, err)
	}
	for name, id := range map[string]shared.ID{"by type": secretType, "by source": secretSource} {
		if st, obs, n := f.observation(t, id); st != "new" || obs != "stale" || n != 1 {
			t.Fatalf("secret %s: status=%s observation=%s activities=%d, want new/stale/1", name, st, obs, n)
		}
	}
	if st, obs, n := f.observation(t, secretFeature); st != "new" || obs != "present" || n != 0 {
		t.Fatalf("feature-branch secret was touched: %s/%s/%d", st, obs, n)
	}
}
