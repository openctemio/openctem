package integration

// Identity version 3 (the CTIS fingerprint recipe v2) re-key of stored
// findings. For every golden result (testdata/dedup: SAST with and without
// code, SCA, container image, secret, misconfiguration, DAST, network VA with
// port and transport, compliance, web3, generic), stored as the previous
// release stored it, it proves:
//
//   - the re-key keeps every finding id, and a version-2 finding gets
//     exactly the key ingest now computes;
//   - re-ingesting the same result after the re-key updates the same row
//     (no new finding) and keeps its triage; a version-1 finding is re-keyed
//     on that sighting;
//   - counts are stable (no split, duplicate or loss);
//   - a second run changes nothing;
//   - down then up restores the same keys;
//   - CI run sightings follow the key.
//
// Further tests: a collision merges through the finding merge and keeps
// triage, and nothing is read or merged across tenants.

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/internal/app/refingerprint"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// freshFinding is a deep copy of f: ingest masks a raw secret in place, so
// every ingest of a golden result needs its own copy.
func freshFinding(t *testing.T, f ctis.Finding) ctis.Finding {
	t.Helper()
	raw, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	var out ctis.Finding
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

type v3Row struct {
	fingerprint string
	version     int
	status      string
}

func v3Rows(t *testing.T, g *goldenRig, tn v2Tenant) map[string]v3Row {
	t.Helper()
	rs, err := g.r.db.Query(`SELECT id, fingerprint, fingerprint_version, status FROM findings
		WHERE tenant_id = $1 AND status <> 'duplicate'`, tn.tenant.String())
	if err != nil {
		t.Fatal(err)
	}
	defer rs.Close()
	out := map[string]v3Row{}
	for rs.Next() {
		var id string
		var r v3Row
		if err := rs.Scan(&id, &r.fingerprint, &r.version, &r.status); err != nil {
			t.Fatal(err)
		}
		out[id] = r
	}
	if err := rs.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// seedCIRun records a CI run that sighted the given keys.
func seedCIRun(t *testing.T, g *goldenRig, tn v2Tenant, keys []string) shared.ID {
	t.Helper()
	asset := shared.NewID()
	if _, err := g.r.db.Exec(`INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, $3, 'repository')`,
		asset.String(), tn.tenant.String(), "ci-"+asset.String()[:8]); err != nil {
		t.Fatalf("seed ci asset: %v", err)
	}
	run := shared.NewID()
	if _, err := g.r.db.Exec(`INSERT INTO ci_runs (id, tenant_id, repository_asset_id, provider, issuer, repository)
		VALUES ($1, $2, $3, 'github', 'https://token.actions.githubusercontent.com', 'acme/app')`,
		run.String(), tn.tenant.String(), asset.String()); err != nil {
		t.Fatalf("seed ci run: %v", err)
	}
	for _, k := range keys {
		if _, err := g.r.db.Exec(`INSERT INTO ci_run_findings (tenant_id, run_id, fingerprint) VALUES ($1, $2, $3)`,
			tn.tenant.String(), run.String(), k); err != nil {
			t.Fatalf("seed ci run finding: %v", err)
		}
	}
	return run
}

func ciRunKeys(t *testing.T, g *goldenRig, run shared.ID) map[string]bool {
	t.Helper()
	rs, err := g.r.db.Query(`SELECT fingerprint FROM ci_run_findings WHERE run_id = $1`, run.String())
	if err != nil {
		t.Fatal(err)
	}
	defer rs.Close()
	out := map[string]bool{}
	for rs.Next() {
		var k string
		if err := rs.Scan(&k); err != nil {
			t.Fatal(err)
		}
		out[k] = true
	}
	if err := rs.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// toPreviousRelease stores a tenant's findings as the previous release
// stored them: a version-2 kind under its version-2 key (the down step does
// exactly that), any other kind under its version-1 key with no tuple.
func toPreviousRelease(t *testing.T, g *goldenRig, tn v2Tenant, file goldenFile, tool string, f ctis.Finding) {
	t.Helper()
	ctx := context.Background()
	store := postgres.NewFindingRekeyRepository(&postgres.DB{DB: g.r.db})
	for id, row := range v3Rows(t, g, tn) {
		res, err := store.Restore(ctx, tn.tenant, id, row.fingerprint)
		if err != nil {
			t.Fatal(err)
		}
		if res.Outcome == vulnerability.RekeyOutcomeRekeyed {
			continue
		}
		var asset string
		if err := g.r.db.QueryRow(`SELECT asset_id FROM findings WHERE id = $1`, id).Scan(&asset); err != nil {
			t.Fatal(err)
		}
		aid, _ := shared.IDFromString(asset)
		v1 := ingest.VersionOneFingerprint(aid, &f, &ctis.Tool{Name: tool})
		if _, err := g.r.db.Exec(`UPDATE findings SET fingerprint = $2, fingerprint_version = 1, identity_key = NULL,
			identity_algo = NULL, identity_fields = NULL WHERE id = $1`, id, v1); err != nil {
			t.Fatal(err)
		}
		// A row written before version 3 never had its version-3 alias.
		if _, err := g.r.db.Exec(`DELETE FROM finding_fingerprints WHERE finding_id = $1 AND fingerprint <> $2`, id, v1); err != nil {
			t.Fatal(err)
		}
	}
	// Nor does a version-2 row have its version-3 alias.
	if _, err := g.r.db.Exec(`DELETE FROM finding_fingerprints a USING findings f
		WHERE a.finding_id = f.id AND f.tenant_id = $1 AND a.version = 3`, tn.tenant.String()); err != nil {
		t.Fatal(err)
	}
}

func TestIdentityV3_GoldenFindingsKeepTheirIdThroughTheRekey(t *testing.T) {
	g := newGoldenRig(t)
	svc := rekeyService(&mergeFixture{t: t, db: g.r.db})
	ctx := context.Background()
	corpus := loadGolden(t)
	for _, name := range sortedKeys(corpus) {
		file := corpus[name]
		for _, c := range file.Cases {
			t.Run(name+"/"+c.Name, func(t *testing.T) {
				tn := g.r.newTenant(file.Tool)
				g.ingest(t, tn, file, file.Tool, freshFinding(t, c.Before))
				current := v3Rows(t, g, tn) // the keys this release computes
				if len(current) == 0 {
					t.Fatal("nothing ingested")
				}
				for id := range current {
					if _, err := g.r.db.Exec(`UPDATE findings SET status = 'false_positive', resolution = 'false_positive' WHERE id = $1`, id); err != nil {
						t.Fatal(err)
					}
				}

				toPreviousRelease(t, g, tn, file, file.Tool, freshFinding(t, c.Before))
				before := v3Rows(t, g, tn)
				oldKeys := make([]string, 0, len(before))
				for _, r := range before {
					oldKeys = append(oldKeys, r.fingerprint)
				}
				run := seedCIRun(t, g, tn, oldKeys)

				rep, err := svc.Run(ctx, tn.tenant, refingerprint.Options{Apply: true})
				if err != nil {
					t.Fatal(err)
				}
				if rep.Merged != 0 {
					t.Fatalf("the re-key merged %d findings of one result", rep.Merged)
				}
				after := v3Rows(t, g, tn)
				if len(after) != len(before) {
					t.Fatalf("%d findings after the re-key, want %d", len(after), len(before))
				}
				for id, was := range before {
					now, ok := after[id]
					if !ok {
						t.Fatalf("finding %s is gone", id)
					}
					if was.version == 2 && (now.version != vulnerability.IdentityVersion || now.fingerprint != current[id].fingerprint) {
						t.Fatalf("version-2 finding re-keyed to %s (v%d), want the ingest key %s", now.fingerprint, now.version, current[id].fingerprint)
					}
					if aliasOwner(t, g.r.db, tn.tenant, was.fingerprint) != id {
						t.Fatalf("the previous key of %s is not its alias", id)
					}
				}
				ci := ciRunKeys(t, g, run)
				for id, now := range after {
					if !ci[now.fingerprint] {
						t.Fatalf("the CI run lost its sighting of %s", id)
					}
				}

				// The same result again, after the re-key: same rows, all on
				// the current key, triage kept.
				g.ingest(t, tn, file, file.Tool, freshFinding(t, c.Before))
				again := v3Rows(t, g, tn)
				if len(again) != len(before) {
					t.Fatalf("%d findings after re-ingest, want %d", len(again), len(before))
				}
				for id, r := range again {
					if _, ok := before[id]; !ok {
						t.Fatalf("re-ingest created finding %s", id)
					}
					if r.version != vulnerability.IdentityVersion || r.fingerprint != current[id].fingerprint {
						t.Fatalf("finding %s on %s (v%d), want %s", id, r.fingerprint, r.version, current[id].fingerprint)
					}
					if r.status != "false_positive" {
						t.Fatalf("finding %s status %s: triage lost", id, r.status)
					}
				}

				second, err := svc.Run(ctx, tn.tenant, refingerprint.Options{Apply: true})
				if err != nil {
					t.Fatal(err)
				}
				if second.Rekeyed != 0 || second.Merged != 0 {
					t.Fatalf("second run changed something: %+v", second)
				}

				// Down then up: the same keys again.
				down, err := svc.RunDown(ctx, tn.tenant, refingerprint.Options{Apply: true})
				if err != nil {
					t.Fatal(err)
				}
				if down.Rekeyed == 0 {
					t.Fatalf("down restored nothing: %+v", down)
				}
				for id, r := range v3Rows(t, g, tn) {
					if r.version >= vulnerability.IdentityVersion {
						t.Fatalf("finding %s still on version %d after down", id, r.version)
					}
				}
				if _, err := svc.Run(ctx, tn.tenant, refingerprint.Options{Apply: true}); err != nil {
					t.Fatal(err)
				}
				for id, r := range v3Rows(t, g, tn) {
					if before[id].version == 2 && r.fingerprint != current[id].fingerprint {
						t.Fatalf("down+up moved %s to %s, want %s", id, r.fingerprint, current[id].fingerprint)
					}
				}
				if n := len(v3Rows(t, g, tn)); n != len(before) {
					t.Fatalf("%d findings after down and up, want %d", n, len(before))
				}
			})
		}
	}
}

// Two stored findings with one version-3 key are one finding: the older
// survives through the finding merge with its triage, the other stays a
// tombstone, nothing is deleted, and the CI run sightings of both follow.
func TestIdentityV3_CollisionMergesThroughTheFindingMerge(t *testing.T) {
	f := newMergeFixture(t, "v3-collide")
	ctx := context.Background()
	k := vulnerability.NewIdentityKey(vulnerability.IdentityKindNetwork,
		vulnerability.IdentityFieldAsset, f.keep.String(), "vuln", "CVE-2024-6387", "port", "22/tcp")
	older := f.v1SCA(f.keep, "pkg:npm/a@1", "CVE-2099-0001", "accepted", time.Now().Add(-48*time.Hour))
	newer := f.v1SCA(f.keep, "pkg:npm/b@1", "CVE-2099-0002", "new", time.Now())
	// Both rows carry a version-2 tuple of the same issue under two keys (a
	// duplicate an earlier recipe failed to fold, written here by hand).
	raw, _ := vulnerability.MarshalIdentityKey(k.AtVersion(2))
	if _, err := f.db.Exec(`UPDATE findings SET fingerprint = $2, fingerprint_version = 2, identity_key = $3::jsonb, component_id = NULL WHERE id = $1`,
		older.String(), k.AtVersion(2).Fingerprint(), string(raw)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.Exec(`UPDATE findings SET fingerprint = $2, fingerprint_version = 3, identity_key = $3::jsonb, component_id = NULL WHERE id = $1`,
		newer.String(), k.Fingerprint(), mustRaw(t, k)); err != nil {
		t.Fatal(err)
	}
	run := seedCIRun(t, &goldenRig{r: &v2Rig{db: f.db, t: t}}, v2Tenant{tenant: f.tenant}, []string{k.AtVersion(2).Fingerprint(), k.Fingerprint()})
	before := f.count(`SELECT count(*) FROM findings WHERE tenant_id = $1`, f.tenant.String())

	rep, err := rekeyService(f).Run(ctx, f.tenant, refingerprint.Options{Apply: true})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Merged != 1 || len(rep.Merges) != 1 || rep.Merges[0].SurvivorID != older.String() || rep.Merges[0].LoserID != newer.String() {
		t.Fatalf("report %+v, want the older finding to survive one merge", rep)
	}
	if got := f.count(`SELECT count(*) FROM findings WHERE tenant_id = $1`, f.tenant.String()); got != before {
		t.Fatalf("%d findings after the merge, want %d (nothing deleted)", got, before)
	}
	if s := f.state(older); s.fingerprint != k.Fingerprint() || s.status != "accepted" {
		t.Fatalf("survivor %+v, want the version-3 key and its triage", s)
	}
	if s := f.state(newer); s.status != "duplicate" {
		t.Fatalf("loser status %s, want duplicate", s.status)
	}
	ci := ciRunKeys(t, &goldenRig{r: &v2Rig{db: f.db, t: t}}, run)
	if len(ci) != 1 || !ci[k.Fingerprint()] {
		t.Fatalf("CI run keys %v, want only the survivor's key", ci)
	}
}

func mustRaw(t *testing.T, k vulnerability.IdentityKey) string {
	t.Helper()
	raw, err := vulnerability.MarshalIdentityKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// The re-key and its down step read and write one tenant only: another
// tenant's version-2 findings with the same tuple values stay untouched, and
// a key that exists in another tenant never causes a merge.
func TestIdentityV3_RekeyNeverCrossesTenants(t *testing.T) {
	a := newMergeFixture(t, "v3-tenant-a")
	b := newMergeFixture(t, "v3-tenant-b")
	ctx := context.Background()
	seed := func(f *mergeFixture) (shared.ID, vulnerability.IdentityKey) {
		id := f.v1SCA(f.keep, "pkg:npm/lodash@4.17.15", "CVE-2021-23337", "accepted", time.Now())
		// One shared asset value makes the two tenants' tuples identical.
		k := vulnerability.NewIdentityKey(vulnerability.IdentityKindSCA,
			vulnerability.IdentityFieldAsset, a.keep.String(), "component", "pkg:npm/lodash", "vuln", "CVE-2021-23337")
		if _, err := f.db.Exec(`UPDATE findings SET fingerprint = $2, fingerprint_version = 2, identity_key = $3::jsonb WHERE id = $1`,
			id.String(), k.AtVersion(2).Fingerprint(), mustRaw(t, k.AtVersion(2))); err != nil {
			t.Fatal(err)
		}
		return id, k
	}
	idA, k := seed(a)
	idB, _ := seed(b)

	rep, err := rekeyService(a).Run(ctx, a.tenant, refingerprint.Options{Apply: true})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Rekeyed != 1 || rep.Merged != 0 {
		t.Fatalf("tenant A report %+v", rep)
	}
	if s := a.state(idA); s.fingerprint != k.Fingerprint() {
		t.Fatalf("tenant A key %s", s.fingerprint)
	}
	if s := b.state(idB); s.fingerprint != k.AtVersion(2).Fingerprint() || s.status != "accepted" {
		t.Fatalf("tenant B's finding changed: %+v", s)
	}
	// Tenant B's tuple names tenant A's asset, so it does not reproduce B's
	// row: refused, never re-keyed onto another tenant's key space.
	repB, err := rekeyService(b).Run(ctx, b.tenant, refingerprint.Options{Apply: true})
	if err != nil {
		t.Fatal(err)
	}
	if repB.Merged != 0 || repB.Rekeyed != 0 || repB.Skipped[vulnerability.RecomputeSkipKeyMismatch] != 1 {
		t.Fatalf("tenant B report %+v, want the foreign tuple refused", repB)
	}
	downB, err := rekeyService(b).RunDown(ctx, b.tenant, refingerprint.Options{Apply: true})
	if err != nil {
		t.Fatal(err)
	}
	if downB.Scanned != 0 {
		t.Fatalf("down for tenant B read %d findings of another tenant", downB.Scanned)
	}
	if s := a.state(idA); s.fingerprint != k.Fingerprint() {
		t.Fatal("tenant B's down step moved tenant A's finding")
	}
}
