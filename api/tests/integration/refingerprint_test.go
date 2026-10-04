package integration

// RFC-043 §6 re-fingerprint job: dry run equals the real run, merges go
// through the earliest-wins finding merge and never delete, old keys become
// aliases, the job is batched, resumable and idempotent, scan auto-resolve is
// paused while a run is open (D11), and every statement stays in its tenant.

import (
	"context"
	"database/sql"
	"net/url"
	"testing"
	"time"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/internal/app/refingerprint"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

func rekeyService(f *mergeFixture) *refingerprint.Service {
	return refingerprint.NewService(postgres.NewFindingRekeyRepository(&postgres.DB{DB: f.db}))
}

// v1SCA inserts a version-1 SCA finding as ingest stored it before version 2:
// a line-free but version-keyed fingerprint, linked to its component.
func (f *mergeFixture) v1SCA(asset shared.ID, purl, cve, status string, created time.Time) shared.ID {
	f.t.Helper()
	var comp string
	if err := f.db.QueryRow(`INSERT INTO components (name, version, ecosystem, purl)
		VALUES ('lodash', $2, 'npm', $1)
		ON CONFLICT (purl) DO UPDATE SET purl = EXCLUDED.purl RETURNING id`, purl, purl[len(purl)-7:]).Scan(&comp); err != nil {
		f.t.Fatalf("component: %v", err)
	}
	id := shared.NewID()
	if _, err := f.db.Exec(`
		INSERT INTO findings (id, tenant_id, asset_id, component_id, source, tool_name, rule_id, cve_id, message,
			severity, status, fingerprint, finding_type, created_at, updated_at)
		VALUES ($1,$2,$3,$4,'sca','trivy',$5,$5,'lodash','high',$6,$7,'vulnerability',$8,$8)`,
		id.String(), f.tenant.String(), asset.String(), comp, cve, status, "v1-"+id.String(), created); err != nil {
		f.t.Fatalf("insert v1 finding: %v", err)
	}
	return id
}

func TestRefingerprint_DryRunEqualsRunAndMergesKeepState(t *testing.T) {
	f := newMergeFixture(t, "refp-merge")
	ctx := context.Background()
	old := f.v1SCA(f.keep, "pkg:npm/lodash@4.17.15", "CVE-2021-23337", "accepted_risk", time.Now().Add(-72*time.Hour))
	newer := f.v1SCA(f.keep, "pkg:npm/lodash@4.17.20", "CVE-2021-23337", "new", time.Now().Add(-time.Hour))
	other := f.v1SCA(f.keep, "pkg:npm/lodash@4.17.20", "CVE-2020-8203", "new", time.Now())
	if _, err := f.db.Exec(`UPDATE findings SET work_item_uris = ARRAY['JIRA-1'] WHERE id = $1`, old.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.Exec(`INSERT INTO finding_comments (tenant_id, finding_id, author_id, content) VALUES ($1,$2,$3,'look here')`,
		f.tenant.String(), newer.String(), f.user.String()); err != nil {
		t.Fatal(err)
	}
	oldKey, newerKey := f.state(old).fingerprint, f.state(newer).fingerprint
	before := f.count(`SELECT count(*) FROM findings WHERE tenant_id = $1`, f.tenant.String())

	svc := rekeyService(f)
	dry, err := svc.Run(ctx, f.tenant, refingerprint.Options{BatchSize: 2})
	if err != nil {
		t.Fatal(err)
	}
	if dry.Rekeyed != 2 || dry.Merged != 1 || len(dry.Merges) != 1 {
		t.Fatalf("dry run: %+v", dry)
	}
	if dry.Merges[0].SurvivorID != old.String() || dry.Merges[0].LoserID != newer.String() {
		t.Fatalf("dry run picks %+v, want the older finding to survive", dry.Merges[0])
	}
	if f.state(old).fingerprint != oldKey || f.count(`SELECT count(*) FROM finding_rekey_runs WHERE tenant_id=$1`, f.tenant.String()) != 0 {
		t.Fatal("the dry run changed something")
	}

	run, err := svc.Run(ctx, f.tenant, refingerprint.Options{Apply: true, BatchSize: 2})
	if err != nil {
		t.Fatal(err)
	}
	if run.Rekeyed != dry.Rekeyed || run.Merged != dry.Merged || len(run.Merges) != 1 || run.Merges[0] != dry.Merges[0] {
		t.Fatalf("dry run %+v differs from the real run %+v", dry, run)
	}

	if n := f.count(`SELECT count(*) FROM findings WHERE tenant_id = $1`, f.tenant.String()); n != before {
		t.Fatalf("%d findings after the run, %d before: a merge deleted a row", n, before)
	}
	s := f.state(old)
	if s.status != "accepted_risk" || len(s.tickets) != 1 {
		t.Fatalf("survivor lost its triage: %+v", s)
	}
	if l := f.state(newer); l.status != "duplicate" || !l.duplicateOf.Valid || l.duplicateOf.String != old.String() {
		t.Fatalf("loser is not a tombstone of the survivor: %+v", l)
	}
	if n := f.count(`SELECT count(*) FROM finding_comments WHERE finding_id = $1`, old.String()); n != 1 {
		t.Fatalf("the loser's comment was not moved (%d)", n)
	}
	for _, k := range []string{oldKey, newerKey} {
		if got := aliasOwner(t, f.db, f.tenant, k); got != old.String() {
			t.Fatalf("old key %s belongs to %q, want the survivor", k, got)
		}
	}
	var version int
	if err := f.db.QueryRow(`SELECT fingerprint_version FROM findings WHERE id = $1`, old.String()).Scan(&version); err != nil || version != 2 {
		t.Fatalf("survivor version %d (%v)", version, err)
	}
	if f.state(other).fingerprint == "v1-"+other.String() {
		t.Fatal("an unrelated finding was not re-keyed")
	}

	again, err := svc.Run(ctx, f.tenant, refingerprint.Options{Apply: true})
	if err != nil {
		t.Fatal(err)
	}
	if again.Rekeyed != 0 || again.Merged != 0 {
		t.Fatalf("a second run changed something: %+v", again)
	}
}

func TestRefingerprint_ResumableAndPausesAutoResolve(t *testing.T) {
	f := newMergeFixture(t, "refp-resume")
	ctx := context.Background()
	ids := []shared.ID{
		f.v1SCA(f.keep, "pkg:npm/lodash@4.17.15", "CVE-2021-1", "new", time.Now().Add(-3*time.Hour)),
		f.v1SCA(f.keep, "pkg:npm/lodash@4.17.15", "CVE-2021-2", "new", time.Now().Add(-2*time.Hour)),
		f.v1SCA(f.keep, "pkg:npm/lodash@4.17.15", "CVE-2021-3", "new", time.Now().Add(-time.Hour)),
	}
	// Scan auto-resolve closes default-branch findings of the same tool that
	// the current scan did not report.
	branch := shared.NewID()
	if _, err := f.db.Exec(`INSERT INTO asset_repositories (asset_id, full_name, default_branch) VALUES ($1, 'org/refp', 'main') ON CONFLICT DO NOTHING`, f.keep.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.Exec(`INSERT INTO repository_branches (id, repository_id, name, branch_type, is_default) VALUES ($1, $2, 'main', 'main', true)`, branch.String(), f.keep.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.Exec(`UPDATE findings SET scan_id = 'old-scan', branch_id = $2 WHERE tenant_id = $1`, f.tenant.String(), branch.String()); err != nil {
		t.Fatal(err)
	}
	svc := rekeyService(f)
	first, err := svc.Run(ctx, f.tenant, refingerprint.Options{Apply: true, BatchSize: 1, MaxBatches: 1})
	if err != nil {
		t.Fatal(err)
	}
	if first.Completed || first.Rekeyed != 1 {
		t.Fatalf("first slice: %+v", first)
	}
	var status string
	if err := f.db.QueryRow(`SELECT status FROM finding_rekey_runs WHERE tenant_id = $1`, f.tenant.String()).Scan(&status); err != nil || status != "running" {
		t.Fatalf("run status %q (%v), want running", status, err)
	}

	// D11: a scan that does not produce the old keys must not close them.
	repo := postgres.NewFindingRepository(&postgres.DB{DB: f.db})
	closed, err := repo.AutoResolveStaleByAssets(ctx, f.tenant, []shared.ID{f.keep}, "trivy", "new-scan", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(closed) != 0 {
		t.Fatalf("auto-resolve closed %d findings while the run was open", len(closed))
	}
	// A run abandoned for longer than the pause window stops pausing (it
	// would otherwise pause the tenant forever); the same call now closes
	// the findings, which also proves the pause was what held it back.
	if _, err := f.db.Exec(`UPDATE finding_rekey_runs SET updated_at = NOW() - INTERVAL '3 hours' WHERE tenant_id = $1`, f.tenant.String()); err != nil {
		t.Fatal(err)
	}
	closed, err = repo.AutoResolveStaleByAssets(ctx, f.tenant, []shared.ID{f.keep}, "trivy", "new-scan", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(closed) != len(ids) {
		t.Fatalf("a stale run still pauses auto-resolve: closed %d of %d", len(closed), len(ids))
	}

	second, err := svc.Run(ctx, f.tenant, refingerprint.Options{Apply: true, BatchSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	if !second.Resumed || !second.Completed || second.Rekeyed != 2 {
		t.Fatalf("resume: %+v", second)
	}
	for _, id := range ids {
		var v int
		if err := f.db.QueryRow(`SELECT fingerprint_version FROM findings WHERE id = $1`, id.String()).Scan(&v); err != nil || v != 2 {
			t.Fatalf("finding %s at version %d", id, v)
		}
	}
	if err := f.db.QueryRow(`SELECT status FROM finding_rekey_runs WHERE tenant_id = $1`, f.tenant.String()).Scan(&status); err != nil || status != "completed" {
		t.Fatalf("run status %q, want completed", status)
	}
}

// A key held in another tenant is not a collision: the job never looks
// outside the tenant it runs for.
func TestRefingerprint_TenantIsolation(t *testing.T) {
	a := newMergeFixture(t, "refp-tenant-a")
	b := newMergeFixture(t, "refp-tenant-b")
	id := a.v1SCA(a.keep, "pkg:npm/lodash@4.17.15", "CVE-2021-23337", "new", time.Now().Add(-time.Hour))
	k, reason := vulnerability.IdentityFromStored(vulnerability.StoredIdentityInput{
		AssetID: a.keep.String(), Source: "sca", FindingType: "vulnerability", RuleID: "CVE-2021-23337",
		CVEID: "CVE-2021-23337", ComponentPURL: "pkg:npm/lodash@4.17.15"})
	if reason != "" {
		t.Fatal(reason)
	}
	// Tenant B has a finding under exactly that key (older, triaged).
	bID := shared.NewID()
	if _, err := b.db.Exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, status,
		fingerprint, created_at, updated_at) VALUES ($1,$2,$3,'sca','trivy','x','high','accepted_risk',$4,$5,$5)`,
		bID.String(), b.tenant.String(), b.keep.String(), k.Fingerprint(), time.Now().Add(-48*time.Hour)); err != nil {
		t.Fatal(err)
	}
	rep, err := rekeyService(a).Run(context.Background(), a.tenant, refingerprint.Options{Apply: true})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Merged != 0 || rep.Rekeyed != 1 {
		t.Fatalf("tenant A's run crossed into tenant B: %+v", rep)
	}
	if s := a.state(id); s.status == "duplicate" || s.fingerprint != k.Fingerprint() {
		t.Fatalf("tenant A finding: %+v", s)
	}
	var st string
	if err := b.db.QueryRow(`SELECT status FROM findings WHERE id = $1`, bID.String()).Scan(&st); err != nil || st != "accepted_risk" {
		t.Fatalf("tenant B's finding changed: %q %v", st, err)
	}
}

// The job's recompute from a stored row gives the key a re-scan gives: for
// every golden result whose row holds the recipe inputs, a version-2 finding
// reset to version 1 is re-keyed back to exactly its ingest key. Results the
// row cannot recompute keep their version-1 key (re-keyed on their next
// sighting, proven by TestDedupGolden_VersionOneFindingsAreReKeyedWithTheirTriage).
func TestRefingerprint_StoredRecomputeMatchesIngest(t *testing.T) {
	g := newGoldenRig(t)
	corpus := loadGolden(t)
	recomputed := 0
	for _, name := range sortedKeys(corpus) {
		file := corpus[name]
		for _, c := range file.Cases {
			t.Run(name+"/"+c.Name, func(t *testing.T) {
				tn := g.r.newTenant(file.Tool)
				g.ingest(t, tn, file, file.Tool, c.Before)
				for _, row := range g.rows(t, tn) {
					asset, _ := shared.IDFromString(row.asset)
					before := c.Before
					v1 := ingest.VersionOneFingerprint(asset, &before, &ctis.Tool{Name: file.Tool}) + "-" + row.id
					if _, err := g.r.db.Exec(`UPDATE findings SET fingerprint = $2, fingerprint_version = 1, identity_key = NULL WHERE id = $1`, row.id, v1); err != nil {
						t.Fatal(err)
					}
					if _, err := g.r.db.Exec(`DELETE FROM finding_fingerprints WHERE finding_id = $1 AND fingerprint <> $2`, row.id, v1); err != nil {
						t.Fatal(err)
					}
				}
				svc := refingerprint.NewService(postgres.NewFindingRekeyRepository(&postgres.DB{DB: g.r.db}))
				rep, err := svc.Run(context.Background(), tn.tenant, refingerprint.Options{Apply: true})
				if err != nil {
					t.Fatal(err)
				}
				if rep.Merged != 0 {
					t.Fatalf("unexpected merge: %+v", rep)
				}
				after := g.rows(t, tn)
				for _, r := range after {
					if r.version == 1 {
						continue // not lossless from the row
					}
					recomputed++
					// The key must be the one ingest gives the result: a re-scan
					// lands on it instead of creating a duplicate.
					g.ingest(t, tn, file, file.Tool, c.Before)
					if n := len(g.rows(t, tn)); n != len(after) {
						t.Fatalf("a re-scan after the job created a duplicate: %d findings, want %d (recomputed key %s differs from ingest)", n, len(after), r.fingerprint)
					}
				}
			})
		}
	}
	if recomputed == 0 {
		t.Fatal("no golden result was recomputed from its row")
	}
	t.Logf("recomputed from the row: %d", recomputed)
}

// A new key held (through an alias) by a finding on another asset is never
// merged automatically: an automatic merge across assets could cross a data
// scope. Dry run and real run both report it as kept.
func TestRefingerprint_NeverMergesAcrossAssets(t *testing.T) {
	f := newMergeFixture(t, "refp-asset")
	ctx := context.Background()
	id := f.v1SCA(f.keep, "pkg:npm/lodash@4.17.15", "CVE-2021-23337", "new", time.Now())
	k, reason := vulnerability.IdentityFromStored(vulnerability.StoredIdentityInput{
		AssetID: f.keep.String(), Source: "sca", FindingType: "vulnerability", RuleID: "CVE-2021-23337",
		CVEID: "CVE-2021-23337", ComponentPURL: "pkg:npm/lodash@4.17.15"})
	if reason != "" {
		t.Fatal(reason)
	}
	elsewhere := shared.NewID()
	if _, err := f.db.Exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, status,
		fingerprint, created_at, updated_at) VALUES ($1,$2,$3,'sca','trivy','x','high','accepted_risk',$4,$5,$5)`,
		elsewhere.String(), f.tenant.String(), f.away.String(), "other-"+elsewhere.String(), time.Now().Add(-48*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.Exec(`INSERT INTO finding_fingerprints (tenant_id, fingerprint, finding_id, version) VALUES ($1,$2,$3,2)`,
		f.tenant.String(), k.Fingerprint(), elsewhere.String()); err != nil {
		t.Fatal(err)
	}
	svc := rekeyService(f)
	for _, apply := range []bool{false, true} {
		rep, err := svc.Run(ctx, f.tenant, refingerprint.Options{Apply: apply})
		if err != nil {
			t.Fatal(err)
		}
		if rep.Merged != 0 || rep.Rekeyed != 0 || rep.Skipped[vulnerability.RekeySkipOtherAsset] != 1 {
			t.Fatalf("apply=%v: %+v", apply, rep)
		}
	}
	if s := f.state(id); s.fingerprint != "v1-"+id.String() || s.status != "new" {
		t.Fatalf("finding changed: %+v", s)
	}
	if s := f.state(elsewhere); s.status != "accepted_risk" || s.duplicateOf.Valid {
		t.Fatalf("the other asset's finding changed: %+v", s)
	}
}

// The dry run only reads: it succeeds on a connection where every
// transaction is read-only, which is how the command opens the database
// without -apply.
func TestRefingerprint_DryRunIsReadOnly(t *testing.T) {
	f := newMergeFixture(t, "refp-readonly")
	f.v1SCA(f.keep, "pkg:npm/lodash@4.17.15", "CVE-2021-23337", "new", time.Now().Add(-time.Hour))
	f.v1SCA(f.keep, "pkg:npm/lodash@4.17.20", "CVE-2021-23337", "new", time.Now())
	u, err := url.Parse(testdb.URL())
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set("default_transaction_read_only", "on")
	u.RawQuery = q.Encode()
	ro, err := sql.Open("postgres", u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ro.Close() })
	if _, err := ro.Exec(`UPDATE findings SET status = status WHERE tenant_id = $1`, f.tenant.String()); err == nil {
		t.Fatal("the read-only connection accepted a write")
	}
	rep, err := refingerprint.NewService(postgres.NewFindingRekeyRepository(&postgres.DB{DB: ro})).
		Run(context.Background(), f.tenant, refingerprint.Options{})
	if err != nil {
		t.Fatalf("dry run on a read-only connection: %v", err)
	}
	if rep.Rekeyed != 1 || rep.Merged != 1 {
		t.Fatalf("dry run: %+v", rep)
	}
}
