package integration

// Findings of a kind identity version 3 added (generic here; compliance and
// web3 take the same path) that are still stored under old keys, and the
// start-up re-key's tenant listing.

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/ctis/v2"

	"github.com/openctemio/openctem/server/internal/app/ingest"
	"github.com/openctemio/openctem/server/internal/app/refingerprint"
	"github.com/openctemio/openctem/server/internal/infra/postgres"
	"github.com/openctemio/openctem/server/pkg/domain/sensor"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/vulnerability"
)

// genericTitled is a generic-kind result whose old (version-1) key depends on
// the title, so two titles of one rule are two stored findings of one issue.
func genericTitled(title string) ctis.Finding {
	return ctis.Finding{Type: "vulnerability", Title: title, Severity: "low", RuleID: "ssh-weak-config"}
}

func hostFile() goldenFile {
	file := goldenFile{Tool: "custom-audit"}
	file.Asset.Type, file.Asset.Value = ctis.AssetTypeHost, "audit.example.com"
	return file
}

// Two findings of a kind version 3 added, stored under two old keys, that
// map to one new key end as ONE open finding: the first is re-keyed on its
// sighting, the other is folded into it (older survives with its triage, the
// other is a tombstone whose key stays an alias) instead of being left under
// a key no report matches, where scan auto-resolve would close it.
func TestIdentityV3_OldKeyFindingsOfANewKindConvergeOnIngest(t *testing.T) {
	for _, sameBatch := range []bool{false, true} {
		name := "separate reports"
		if sameBatch {
			name = "one report"
		}
		t.Run(name, func(t *testing.T) {
			g := newGoldenRig(t)
			file := hostFile()
			tn := g.r.newTenant(file.Tool)
			f1, f2 := genericTitled("Weak SSH configuration"), genericTitled("SSH allows weak configuration")

			g.ingest(t, tn, file, file.Tool, freshFinding(t, f1))
			rows := v3Rows(t, g, tn)
			if len(rows) != 1 {
				t.Fatalf("%d findings, want 1", len(rows))
			}
			var id1 string
			for id := range rows {
				id1 = id
			}
			key := rows[id1].fingerprint
			asset := ""
			if err := g.r.db.QueryRow(`SELECT asset_id FROM findings WHERE id = $1`, id1).Scan(&asset); err != nil {
				t.Fatal(err)
			}
			aid, _ := shared.IDFromString(asset)
			// The second stored finding: the same tuple under another old key,
			// as the previous release left two titles of one rule.
			id2 := shared.NewID().String()
			if _, err := g.r.db.Exec(`
				INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, rule_id, title, severity, status,
					fingerprint, fingerprint_version, message, finding_type)
				SELECT $2, tenant_id, asset_id, source, tool_name, rule_id, $3, severity, 'new',
					'old-key-2', 1, message, finding_type FROM findings WHERE id = $1`,
				id1, id2, f2.Title); err != nil {
				t.Fatalf("seed the second row: %v", err)
			}
			v1a := ingest.VersionOneFingerprint(aid, &f1, &ctis.Tool{Name: file.Tool})
			v1b := ingest.VersionOneFingerprint(aid, &f2, &ctis.Tool{Name: file.Tool})
			if v1a == v1b {
				t.Fatal("the two titles must give two old keys")
			}
			for id, v1 := range map[string]string{id1: v1a, id2: v1b} {
				if _, err := g.r.db.Exec(`UPDATE findings SET fingerprint = $2, fingerprint_version = 1, identity_key = NULL,
					identity_algo = NULL, identity_fields = NULL WHERE id = $1`, id, v1); err != nil {
					t.Fatal(err)
				}
				if _, err := g.r.db.Exec(`DELETE FROM finding_fingerprints WHERE finding_id = $1 AND fingerprint <> $2`, id, v1); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := g.r.db.Exec(`UPDATE findings SET created_at = NOW() - interval '48 hours', status = 'accepted' WHERE id = $1`, id1); err != nil {
				t.Fatal(err)
			}

			if sameBatch {
				tid := tn.tenant
				agt := &sensor.Sensor{ID: tn.sensor, TenantID: &tid, Type: sensor.SensorTypeWorker, Status: sensor.SensorStatusActive}
				a, b := freshFinding(t, f1), freshFinding(t, f2)
				a.AssetRef, b.AssetRef = "a", "a"
				rep := &ctis.Report{Version: ctis.SchemaVersion, Tool: &ctis.Tool{Name: file.Tool},
					Metadata: ctis.ReportMetadata{ID: ctis.NewReportID(), GeneratedAt: time.Now().UTC()},
					Assets:   []ctis.Asset{{ID: "a", Type: file.Asset.Type, Value: tn.tenant.String()[:8] + "." + file.Asset.Value}},
					Findings: []ctis.Finding{a, b}}
				if out, err := g.svc.Ingest(context.Background(), agt, ingest.Input{Report: rep}); err != nil || len(out.Errors) > 0 {
					t.Fatalf("ingest: %v %v", err, out.Errors)
				}
			} else {
				g.ingest(t, tn, file, file.Tool, freshFinding(t, f1))
				g.ingest(t, tn, file, file.Tool, freshFinding(t, f2))
			}

			live := v3Rows(t, g, tn)
			if len(live) != 1 {
				t.Fatalf("%d live findings after the sightings, want 1 (%v)", len(live), live)
			}
			surv, ok := live[id1]
			if !ok || surv.status != "accepted" || surv.version != vulnerability.IdentityVersion || surv.fingerprint != key {
				t.Fatalf("survivor %+v, want the older finding, accepted, on key %s", live, key)
			}
			var status string
			if err := g.r.db.QueryRow(`SELECT status FROM findings WHERE id = $1`, id2).Scan(&status); err != nil {
				t.Fatal(err)
			}
			if status != "duplicate" {
				t.Fatalf("leftover status %q, want duplicate (a tombstone, never open or resolved)", status)
			}
			for _, old := range []string{v1a, v1b} {
				var to string
				if err := g.r.db.QueryRow(`SELECT finding_id FROM finding_fingerprints WHERE tenant_id = $1 AND fingerprint = $2`,
					tn.tenant.String(), old).Scan(&to); err != nil || to != id1 {
					t.Fatalf("old key %s resolves to %q (%v), want the survivor", old, to, err)
				}
			}
		})
	}
}

// The start-up run lists only tenants without a completed run to the current
// version (the findings table is not read for the others).
func TestIdentityV3_TenantsToRekeySkipsCompletedRuns(t *testing.T) {
	g := newGoldenRig(t)
	file := hostFile()
	done, pending := g.r.newTenant(file.Tool), g.r.newTenant(file.Tool)
	f := genericTitled("Weak SSH configuration")
	for _, tn := range []v2Tenant{done, pending} {
		g.ingest(t, tn, file, file.Tool, freshFinding(t, f))
		toPreviousRelease(t, g, tn, file, file.Tool, freshFinding(t, f))
	}
	store := postgres.NewFindingRekeyRepository(&postgres.DB{DB: g.r.db})
	ctx := context.Background()
	has := func(ids []shared.ID, want shared.ID) bool {
		for _, id := range ids {
			if id == want {
				return true
			}
		}
		return false
	}
	ids, err := store.TenantsToRekey(ctx, vulnerability.IdentityVersion)
	if err != nil || !has(ids, done.tenant) || !has(ids, pending.tenant) {
		t.Fatalf("before any run: %v %v", ids, err)
	}
	if _, err := refingerprint.NewService(store).Run(ctx, done.tenant, refingerprint.Options{Apply: true}); err != nil {
		t.Fatal(err)
	}
	// Findings of the completed tenant fall back to an old key; the run
	// table, not the findings, decides.
	toPreviousRelease(t, g, done, file, file.Tool, freshFinding(t, f))
	ids, err = store.TenantsToRekey(ctx, vulnerability.IdentityVersion)
	if err != nil || has(ids, done.tenant) || !has(ids, pending.tenant) {
		t.Fatalf("after the run: %v %v, want only the tenant without a completed run", ids, err)
	}
}
