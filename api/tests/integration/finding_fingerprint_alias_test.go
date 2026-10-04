package integration

// RFC-043 §6 (item 10): every key a finding has had is an alias of it, per
// tenant. A re-key (recipe change, asset merge) or a merge into another
// finding keeps the old key resolving, so a report that still produces it
// lands on the finding that carries it now instead of creating a new one.

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func aliasOwner(t *testing.T, db *sql.DB, tenant shared.ID, fp string) string {
	t.Helper()
	var id string
	err := db.QueryRow(`SELECT finding_id FROM finding_fingerprints WHERE tenant_id = $1 AND fingerprint = $2`,
		tenant.String(), fp).Scan(&id)
	if err == sql.ErrNoRows {
		return ""
	}
	if err != nil {
		t.Fatalf("read alias: %v", err)
	}
	return id
}

// Insert and re-key keep every key; a tombstone's placeholder is never one.
func TestFindingFingerprintAlias_TriggersKeepEveryKey(t *testing.T) {
	f := newMergeFixture(t, "alias-trigger")
	id := f.composite(f.keep, "base-a", "new", time.Now())
	first := f.state(id).fingerprint
	if got := aliasOwner(t, f.db, f.tenant, first); got != id.String() {
		t.Fatalf("insert: alias of the current key = %q, want %s", got, id)
	}

	if _, err := f.db.Exec(`UPDATE findings SET fingerprint = 'rekeyed-a', fingerprint_version = 2 WHERE id = $1`, id.String()); err != nil {
		t.Fatal(err)
	}
	if got := aliasOwner(t, f.db, f.tenant, first); got != id.String() {
		t.Fatalf("re-key: the former key must stay an alias of the finding, got %q", got)
	}
	if got := aliasOwner(t, f.db, f.tenant, "rekeyed-a"); got != id.String() {
		t.Fatalf("re-key: the new key must be an alias, got %q", got)
	}
	var v int
	if err := f.db.QueryRow(`SELECT version FROM finding_fingerprints WHERE tenant_id = $1 AND fingerprint = 'rekeyed-a'`,
		f.tenant.String()).Scan(&v); err != nil || v != 2 {
		t.Fatalf("new key version = %d (%v), want 2", v, err)
	}

	if _, err := f.db.Exec(`UPDATE findings SET fingerprint = 'dup:' || id::text WHERE id = $1`, id.String()); err != nil {
		t.Fatal(err)
	}
	if n := f.count(`SELECT count(*) FROM finding_fingerprints WHERE fingerprint LIKE 'dup:%'`); n != 0 {
		t.Fatalf("%d tombstone placeholders stored as aliases", n)
	}

	repo := postgres.NewFindingRepository(&postgres.DB{DB: f.db})
	if _, err := f.db.Exec(`UPDATE findings SET fingerprint = 'rekeyed-b' WHERE id = $1`, id.String()); err != nil {
		t.Fatal(err)
	}
	got, err := repo.ResolveFingerprintAliases(context.Background(), f.tenant, []string{first, "rekeyed-a", "rekeyed-b", "nobody"})
	if err != nil {
		t.Fatal(err)
	}
	if got[first] != "rekeyed-b" || got["rekeyed-a"] != "rekeyed-b" {
		t.Fatalf("former keys resolve to %v, want both -> rekeyed-b", got)
	}
	if _, ok := got["rekeyed-b"]; ok {
		t.Fatal("a current key must not be reported as an alias")
	}
	if _, ok := got["nobody"]; ok {
		t.Fatal("an unknown key resolved")
	}
}

// A key that a finding gave up and another finding now holds belongs to the
// holder.
func TestFindingFingerprintAlias_CurrentHolderWins(t *testing.T) {
	f := newMergeFixture(t, "alias-holder")
	a := f.composite(f.keep, "base-a", "new", time.Now().Add(-time.Hour))
	key := f.state(a).fingerprint
	if _, err := f.db.Exec(`UPDATE findings SET fingerprint = 'moved-on' WHERE id = $1`, a.String()); err != nil {
		t.Fatal(err)
	}
	b := f.composite(f.keep, "base-a", "new", time.Now()) // takes the same key
	if got := aliasOwner(t, f.db, f.tenant, key); got != b.String() {
		t.Fatalf("alias owner = %q, want the current holder %s", got, b)
	}
	repo := postgres.NewFindingRepository(&postgres.DB{DB: f.db})
	got, err := repo.ResolveFingerprintAliases(context.Background(), f.tenant, []string{key})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("a held key resolved elsewhere: %v", got)
	}
}

// Tenant isolation: an alias cannot point at another tenant's finding, and a
// lookup never resolves another tenant's key.
func TestFindingFingerprintAlias_TenantIsolation(t *testing.T) {
	a := newMergeFixture(t, "alias-tenant-a")
	b := newMergeFixture(t, "alias-tenant-b")
	id := a.composite(a.keep, "base-x", "new", time.Now())
	former := a.state(id).fingerprint
	if _, err := a.db.Exec(`UPDATE findings SET fingerprint = 'a-now' WHERE id = $1`, id.String()); err != nil {
		t.Fatal(err)
	}

	if _, err := b.db.Exec(`INSERT INTO finding_fingerprints (tenant_id, fingerprint, finding_id, version)
		VALUES ($1, 'stolen', $2, 1)`, b.tenant.String(), id.String()); err == nil {
		t.Fatal("an alias of tenant B pointing at tenant A's finding was accepted")
	}

	repo := postgres.NewFindingRepository(&postgres.DB{DB: b.db})
	got, err := repo.ResolveFingerprintAliases(context.Background(), b.tenant, []string{former})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("tenant B resolved tenant A's key: %v", got)
	}
	got, err = repo.ResolveFingerprintAliases(context.Background(), a.tenant, []string{former})
	if err != nil {
		t.Fatal(err)
	}
	if got[former] != "a-now" {
		t.Fatalf("tenant A's own key resolves to %v, want a-now", got)
	}
}

// An asset merge that folds two findings into one keeps the loser's key and
// the survivor's key on the merged-away asset; both resolve to the survivor.
func TestAssetMerge_FormerKeysResolveToTheSurvivor(t *testing.T) {
	f := newMergeFixture(t, "alias-merge")
	old := time.Now().Add(-48 * time.Hour)
	survivor := f.composite(f.away, "base-shared", "new", old)
	loser := f.composite(f.keep, "base-shared", "new", time.Now())
	survivorAwayKey := f.state(survivor).fingerprint
	loserKey := f.state(loser).fingerprint
	f.merge()

	if s := f.state(loser); s.status != "duplicate" {
		t.Fatalf("loser status = %s, want duplicate", s.status)
	}
	if got := f.state(survivor).fingerprint; got != loserKey {
		t.Fatalf("survivor key = %s, want the kept asset's key %s", got, loserKey)
	}
	if got := aliasOwner(t, f.db, f.tenant, survivorAwayKey); got != survivor.String() {
		t.Fatalf("the survivor's key on the merged-away asset belongs to %q, want %s", got, survivor)
	}
	if n := f.count(`SELECT count(*) FROM finding_fingerprints WHERE finding_id = $1`, loser.String()); n != 0 {
		t.Fatalf("the tombstone still owns %d aliases", n)
	}
	repo := postgres.NewFindingRepository(&postgres.DB{DB: f.db})
	got, err := repo.ResolveFingerprintAliases(context.Background(), f.tenant, []string{survivorAwayKey})
	if err != nil {
		t.Fatal(err)
	}
	if got[survivorAwayKey] != loserKey {
		t.Fatalf("former key resolves to %v, want %s", got, loserKey)
	}
}

// Ingest looks a key up by alias: after the finding is re-keyed (as a recipe
// migration does), the same report updates it instead of creating a second
// finding, and the sensor check reports the old key as known.
func TestIngest_FormerKeyLandsOnTheFinding(t *testing.T) {
	r := newV2Rig(t, ingest.DefaultBlindingGuard())
	tn := r.newTenant("trivy")
	db := &postgres.DB{DB: r.db}
	svc := ingest.NewService(
		postgres.NewAssetRepository(db), postgres.NewFindingRepository(db),
		postgres.NewVulnerabilityRepository(db), postgres.NewComponentRepository(db),
		postgres.NewSensorRepository(db), postgres.NewBranchRepository(db), postgres.NewTenantRepository(db),
		postgres.NewAuditRepository(db), logger.NewNop())
	tid := tn.tenant
	agt := &sensor.Sensor{ID: tn.sensor, TenantID: &tid, Type: sensor.SensorTypeWorker, Status: sensor.SensorStatusActive}
	scan := func() {
		t.Helper()
		rep := &ctis.Report{Version: "1.0", Tool: &ctis.Tool{Name: "trivy"},
			Metadata: ctis.ReportMetadata{ID: shared.NewID().String(), Timestamp: time.Now().UTC()},
			Assets:   []ctis.Asset{{ID: "h", Type: ctis.AssetTypeHost, Value: "alias-" + tn.tenant.String()[:8] + ".example.com"}},
			Findings: []ctis.Finding{{Type: ctis.FindingTypeVulnerability, Title: "OpenSSH regreSSHion",
				Severity: ctis.SeverityHigh, RuleID: "CVE-2024-6387", AssetRef: "h",
				Vulnerability: &ctis.VulnerabilityDetails{CVEID: "CVE-2024-6387"},
				Network:       &ctis.NetworkLocation{Port: 22, Protocol: "tcp"}}}}
		out, err := svc.Ingest(context.Background(), agt, ingest.Input{Report: rep})
		if err != nil || len(out.Errors) > 0 {
			t.Fatalf("ingest: %v %v", err, out.Errors)
		}
	}
	scan()
	var id, former string
	if err := r.db.QueryRow(`SELECT id, fingerprint FROM findings WHERE tenant_id = $1`, tn.tenant.String()).Scan(&id, &former); err != nil {
		t.Fatal(err)
	}
	if _, err := r.db.Exec(`UPDATE findings SET fingerprint = 'recipe-v2-key', fingerprint_version = 2,
		status = 'false_positive', resolution = 'false_positive' WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}

	scan()

	var n, occurrences int
	var status string
	if err := r.db.QueryRow(`SELECT count(*), max(occurrence_count), max(status) FROM findings WHERE tenant_id = $1`,
		tn.tenant.String()).Scan(&n, &occurrences, &status); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("%d findings after re-ingesting under the former key, want 1", n)
	}
	if status != "false_positive" {
		t.Fatalf("status = %s, want false_positive (triage lost)", status)
	}

	res, err := svc.CheckFingerprints(context.Background(), agt, ingest.CheckFingerprintsInput{Fingerprints: []string{former, "unknown-key"}})
	if err != nil {
		t.Fatal(err)
	}
	existing, missing := res.Existing, res.Missing
	if len(existing) != 1 || existing[0] != former || len(missing) != 1 {
		t.Fatalf("check: existing=%v missing=%v, want the former key known", existing, missing)
	}
}
