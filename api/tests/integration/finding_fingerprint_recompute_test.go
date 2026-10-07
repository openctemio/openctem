package integration

import (
	"context"
	"database/sql"
	"sort"
	"testing"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// An asset merge re-keys the merged assets' findings for the kept asset inside
// the merge transaction, and folds a finding both assets carry into ONE
// survivor — the earliest created — without deleting anything (RFC-043 §9).
// Before, a post-commit recompute deleted the moved copy on collision, and
// with it (ON DELETE CASCADE) its comments, activities, approvals, evidence and
// retests, keeping whichever copy happened to sit on the kept asset.

type mergeFixture struct {
	t      *testing.T
	db     *sql.DB
	tenant shared.ID
	keep   shared.ID
	away   shared.ID
	user   shared.ID
}

func newMergeFixture(t *testing.T, name string) *mergeFixture {
	t.Helper()
	db := setupTestDB(t)
	t.Cleanup(func() { _ = db.Close() })
	f := &mergeFixture{t: t, db: db, tenant: createTestTenant(t, db, name)}
	f.keep = createTestAsset(t, db, f.tenant, name+"-keep")
	f.away = createTestAsset(t, db, f.tenant, name+"-away")
	f.user = shared.NewID()
	if _, err := db.Exec(`INSERT INTO users (id, email, name) VALUES ($1, $2, 'merge test')`,
		f.user.String(), "merge-"+f.user.String()+"@example.test"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM findings WHERE tenant_id=$1`, f.tenant.String())
		_, _ = db.Exec(`DELETE FROM assets WHERE tenant_id=$1`, f.tenant.String())
		_, _ = db.Exec(`DELETE FROM tenants WHERE id=$1`, f.tenant.String())
		_, _ = db.Exec(`DELETE FROM users WHERE id=$1`, f.user.String())
	})
	return f
}

// composite inserts a finding as ingest stores it: composite fingerprint plus
// the persisted base.
func (f *mergeFixture) composite(asset shared.ID, base, status string, created time.Time) shared.ID {
	f.t.Helper()
	id := shared.NewID()
	_, err := f.db.Exec(`
		INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message,
			severity, status, fingerprint, partial_fingerprints, created_at, updated_at)
		VALUES ($1,$2,$3,'sca','trivy','finding','high',$4,$5,$6,$7,$7)`,
		id.String(), f.tenant.String(), asset.String(), status,
		vulnerability.CompositeFingerprint(asset.String(), base),
		`{"`+vulnerability.FingerprintBaseKey+`":"`+base+`"}`, created)
	if err != nil {
		f.t.Fatalf("insert finding: %v", err)
	}
	return id
}

func (f *mergeFixture) merge() {
	f.t.Helper()
	var reviewID string
	if err := f.db.QueryRow(`
		INSERT INTO asset_dedup_review (tenant_id, keep_asset_id, merge_asset_ids, keep_asset_name,
			merge_asset_names, normalized_name, asset_type, status)
		VALUES ($1,$2,ARRAY[$3]::uuid[],'keep',ARRAY['away'],'x','repository','pending') RETURNING id`,
		f.tenant.String(), f.keep.String(), f.away.String()).Scan(&reviewID); err != nil {
		f.t.Fatalf("seed review: %v", err)
	}
	repo := postgres.NewAssetDedupRepository(&postgres.DB{DB: f.db})
	if err := repo.ApproveAndMerge(context.Background(), f.tenant.String(), reviewID, shared.NewID().String(), nil); err != nil {
		f.t.Fatalf("merge: %v", err)
	}
}

type findingState struct {
	asset, fingerprint, status, resolution string
	duplicateOf                            sql.NullString
	tickets                                []string
}

func (f *mergeFixture) state(id shared.ID) findingState {
	f.t.Helper()
	var s findingState
	if err := f.db.QueryRow(`SELECT asset_id, fingerprint, status, COALESCE(resolution,''), duplicate_of::text,
			COALESCE(work_item_uris, '{}') FROM findings WHERE id=$1`, id.String()).
		Scan(&s.asset, &s.fingerprint, &s.status, &s.resolution, &s.duplicateOf, pq.Array(&s.tickets)); err != nil {
		f.t.Fatalf("read finding %s: %v", id, err)
	}
	return s
}

func (f *mergeFixture) count(q string, args ...any) int {
	f.t.Helper()
	var n int
	if err := f.db.QueryRow(q, args...).Scan(&n); err != nil {
		f.t.Fatalf("%s: %v", q, err)
	}
	return n
}

// The merged asset's copy is older and carries a risk acceptance, a ticket and
// a comment; the kept asset's copy is newer and untriaged. The older one
// survives with everything; the newer one becomes its tombstone.
func TestApproveAndMerge_KeepsTriagedFindingAndItsHistory(t *testing.T) {
	f := newMergeFixture(t, "merge-triage")
	old := time.Now().Add(-48 * time.Hour)
	triaged := f.composite(f.away, "base-shared", "new", old)
	fresh := f.composite(f.keep, "base-shared", "new", old.Add(24*time.Hour))
	if _, err := f.db.Exec(`UPDATE findings SET status='accepted_risk', resolution='accepted_risk',
			work_item_uris='{https://jira.example/browse/RISK-1}' WHERE id=$1`, triaged.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.Exec(`UPDATE findings SET work_item_uris='{https://jira.example/browse/SEC-2}' WHERE id=$1`, fresh.String()); err != nil {
		t.Fatal(err)
	}
	commentID := shared.NewID()
	if _, err := f.db.Exec(`INSERT INTO finding_comments (id, tenant_id, finding_id, content, author_id)
			VALUES ($1,$2,$3,'risk accepted by CISO',$4)`, commentID.String(), f.tenant.String(), triaged.String(), f.user.String()); err != nil {
		t.Fatalf("seed comment: %v", err)
	}
	before := f.count(`SELECT count(*) FROM findings WHERE tenant_id=$1`, f.tenant.String())

	f.merge()

	if after := f.count(`SELECT count(*) FROM findings WHERE tenant_id=$1`, f.tenant.String()); after != before {
		t.Fatalf("a merge must not delete findings: %d before, %d after", before, after)
	}
	s := f.state(triaged)
	wantFP := vulnerability.CompositeFingerprint(f.keep.String(), "base-shared")
	if s.asset != f.keep.String() || s.fingerprint != wantFP {
		t.Errorf("survivor not re-keyed onto the kept asset: asset=%s fp=%s", s.asset, s.fingerprint)
	}
	if s.status != "accepted_risk" || s.resolution != "accepted_risk" {
		t.Errorf("survivor lost its risk acceptance: status=%s resolution=%s", s.status, s.resolution)
	}
	if len(s.tickets) != 2 {
		t.Errorf("survivor should carry both ticket links, got %v", s.tickets)
	}
	d := f.state(fresh)
	if d.status != "duplicate" || !d.duplicateOf.Valid || d.duplicateOf.String != triaged.String() {
		t.Errorf("newer copy should be a duplicate of the survivor, got status=%s duplicate_of=%v", d.status, d.duplicateOf)
	}
	if n := f.count(`SELECT count(*) FROM finding_comments WHERE id=$1 AND finding_id=$2`, commentID.String(), triaged.String()); n != 1 {
		t.Errorf("the comment was lost or moved off the survivor")
	}
	if n := f.count(`SELECT count(*) FROM finding_activities WHERE finding_id=$1 AND activity_type='duplicate_marked'`, triaged.String()); n != 1 {
		t.Errorf("survivor has no merge activity")
	}
}

// The kept asset's copy is older but untriaged; the merged asset's newer copy
// is a false positive with a comment. The older one survives and inherits the
// deliberate disposition and the comment.
func TestApproveAndMerge_SurvivorInheritsStrongerStateAndChildren(t *testing.T) {
	f := newMergeFixture(t, "merge-inherit")
	old := time.Now().Add(-48 * time.Hour)
	keepCopy := f.composite(f.keep, "base-x", "new", old)
	awayCopy := f.composite(f.away, "base-x", "false_positive", old.Add(time.Hour))
	if _, err := f.db.Exec(`INSERT INTO finding_comments (tenant_id, finding_id, content, author_id) VALUES ($1,$2,'FP: test fixture',$3)`,
		f.tenant.String(), awayCopy.String(), f.user.String()); err != nil {
		t.Fatalf("seed comment: %v", err)
	}

	f.merge()

	if s := f.state(keepCopy); s.status != "false_positive" {
		t.Errorf("survivor should inherit false_positive, got %s", s.status)
	}
	if d := f.state(awayCopy); d.status != "duplicate" || d.duplicateOf.String != keepCopy.String() {
		t.Errorf("loser not tombstoned: %+v", d)
	}
	if n := f.count(`SELECT count(*) FROM finding_comments WHERE finding_id=$1`, keepCopy.String()); n != 1 {
		t.Errorf("loser's comment should move to the survivor, survivor has %d", n)
	}
}

// A resolved (fixed) loser never closes a survivor that is still open.
func TestApproveAndMerge_FixedLoserDoesNotCloseOpenSurvivor(t *testing.T) {
	f := newMergeFixture(t, "merge-fixed")
	old := time.Now().Add(-48 * time.Hour)
	open := f.composite(f.keep, "base-y", "in_progress", old)
	fixed := f.composite(f.away, "base-y", "resolved", old.Add(time.Hour))
	f.merge()
	if s := f.state(open); s.status != "in_progress" {
		t.Errorf("open survivor was closed by a fixed duplicate: %s", s.status)
	}
	if d := f.state(fixed); d.status != "duplicate" {
		t.Errorf("fixed copy should be a duplicate, got %s", d.status)
	}
}

// Findings without a collision are re-keyed; ones that cannot be recomputed
// safely are left as they are.
func TestApproveAndMerge_RekeysWithoutCollision(t *testing.T) {
	f := newMergeFixture(t, "merge-rekey")
	unique := f.composite(f.away, "base-unique", "new", time.Now())

	legacy := shared.NewID()
	legacyFP := vulnerability.CompositeFingerprint(f.away.String(), "legacy")
	if _, err := f.db.Exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message,
			severity, status, fingerprint, partial_fingerprints) VALUES ($1,$2,$3,'sca','trivy','legacy','low','new',$4,'{}')`,
		legacy.String(), f.tenant.String(), f.away.String(), legacyFP); err != nil {
		t.Fatal(err)
	}
	manual := shared.NewID()
	if _, err := f.db.Exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, rule_id,
			file_path, start_line, severity, status, fingerprint) VALUES ($1,$2,$3,'manual','manual','m','R1','a.go',7,'low','new',$4)`,
		manual.String(), f.tenant.String(), f.away.String(),
		vulnerability.ManualFingerprint(f.away.String(), "R1", "a.go", 7, "m")); err != nil {
		t.Fatal(err)
	}

	f.merge()

	if s := f.state(unique); s.fingerprint != vulnerability.CompositeFingerprint(f.keep.String(), "base-unique") {
		t.Errorf("unique finding not re-keyed: %s", s.fingerprint)
	}
	if s := f.state(legacy); s.fingerprint != legacyFP {
		t.Errorf("finding without a stored base must keep its fingerprint, got %s", s.fingerprint)
	}
	if s := f.state(manual); s.fingerprint != vulnerability.ManualFingerprint(f.keep.String(), "R1", "a.go", 7, "m") {
		t.Errorf("manual finding not re-keyed: %s", s.fingerprint)
	}
}

// Both copies have a retest in flight. A finding allows one pending retest,
// so the survivor's keeps running, the loser's is closed as unknown, and every
// retest of the loser ends up on the survivor.
func TestApproveAndMerge_MovesRetestsWithOnePending(t *testing.T) {
	f := newMergeFixture(t, "merge-retests")
	old := time.Now().Add(-48 * time.Hour)
	survivor := f.composite(f.away, "base-r", "new", old)
	loser := f.composite(f.keep, "base-r", "new", old.Add(time.Hour))
	retest := func(finding shared.ID, status string) string {
		t.Helper()
		id := shared.NewID().String()
		q := `INSERT INTO finding_retests (id, tenant_id, finding_id, trigger, status, prior_status,
				template_id, target, deadline_at) VALUES ($1,$2,$3,'manual','pending','new','tpl','https://a.example',NOW()+interval '1 hour')`
		if status == "completed" {
			q = `INSERT INTO finding_retests (id, tenant_id, finding_id, trigger, status, outcome, completed_at,
				prior_status, template_id, target, deadline_at) VALUES ($1,$2,$3,'manual','completed','not_reproduced',NOW(),
				'new','tpl','https://a.example',NOW()-interval '1 hour')`
		}
		if _, err := f.db.Exec(q, id, f.tenant.String(), finding.String()); err != nil {
			t.Fatalf("seed retest: %v", err)
		}
		return id
	}
	survivorPending := retest(survivor, "pending")
	loserPending := retest(loser, "pending")
	loserDone := retest(loser, "completed")

	f.merge()

	if n := f.count(`SELECT count(*) FROM finding_retests WHERE finding_id=$1`, survivor.String()); n != 3 {
		t.Fatalf("survivor should hold all 3 retests, has %d", n)
	}
	if n := f.count(`SELECT count(*) FROM finding_retests WHERE finding_id=$1 AND status='pending'`, survivor.String()); n != 1 {
		t.Fatalf("survivor should have exactly 1 pending retest, has %d", n)
	}
	if n := f.count(`SELECT count(*) FROM finding_retests WHERE id=$1 AND status='pending'`, survivorPending); n != 1 {
		t.Error("the survivor's own pending retest must keep running")
	}
	if n := f.count(`SELECT count(*) FROM finding_retests WHERE id=$1 AND status='completed' AND outcome='inconclusive'`, loserPending); n != 1 {
		t.Error("the loser's pending retest must be closed as unknown")
	}
	if n := f.count(`SELECT count(*) FROM finding_retests WHERE id=$1 AND outcome='not_reproduced'`, loserDone); n != 1 {
		t.Error("the loser's completed retest must keep its outcome")
	}
}

// Every reference to findings.id must be re-pointed by a finding merge, so a
// new table cannot lose rows to a tombstone silently.
func TestFindingMergeCoversEveryFindingReference(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	rows, err := db.Query(`
		SELECT c.conrelid::regclass::text || '.' || a.attname
		FROM pg_constraint c
		JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = c.conkey[1]
		WHERE c.contype = 'f' AND c.confrelid = 'findings'::regclass`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	schema := map[string]bool{}
	for rows.Next() {
		var ref string
		if err := rows.Scan(&ref); err != nil {
			t.Fatal(err)
		}
		schema[ref] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	handled := postgres.FindingMergeReferenceHandling()
	var missing, stale []string
	for ref := range schema {
		if _, ok := handled[ref]; !ok {
			missing = append(missing, ref)
		}
	}
	for ref := range handled {
		if !schema[ref] {
			stale = append(stale, ref)
		}
	}
	sort.Strings(missing)
	sort.Strings(stale)
	if len(missing) > 0 {
		t.Errorf("finding merge does not re-point these references; add them to findingMergeRefs: %v", missing)
	}
	if len(stale) > 0 {
		t.Errorf("findingMergeRefs names references that are not in the schema: %v", stale)
	}
}
