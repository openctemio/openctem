package integration

// RFC-043 §11.2 golden corpus: per tool, pairs of results {before, after,
// expect same|different} run through the real ingest service on a migrated
// database. For every pair it proves two things:
//
//  1. Re-scans map to the same finding (or not) as the version-2 recipe
//     says: "same" means the second result updates the first finding,
//     "different" means it creates one more.
//  2. Version 1 to version 2 is stable: a finding stored under its
//     version-1 key, and triaged, is re-keyed to its version-2 key the next
//     time the same result arrives, keeps its triage, and its version-1 key
//     stays an alias. No duplicate appears.
//
// A recipe change must state which golden pairs change outcome.

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type goldenCase struct {
	Name      string       `json:"name"`
	Expect    string       `json:"expect"`
	Before    ctis.Finding `json:"before"`
	After     ctis.Finding `json:"after"`
	AfterTool string       `json:"after_tool"`
}

type goldenFile struct {
	Tool  string `json:"tool"`
	Asset struct {
		Type  ctis.AssetType `json:"type"`
		Value string         `json:"value"`
	} `json:"asset"`
	Cases []goldenCase `json:"cases"`
}

type goldenRig struct {
	r   *v2Rig
	svc *ingest.Service
}

func newGoldenRig(t *testing.T) *goldenRig {
	t.Helper()
	r := newV2Rig(t, ingest.DefaultBlindingGuard())
	db := &postgres.DB{DB: r.db}
	svc := ingest.NewService(
		postgres.NewAssetRepository(db), postgres.NewFindingRepository(db),
		postgres.NewVulnerabilityRepository(db), postgres.NewComponentRepository(db),
		postgres.NewSensorRepository(db), postgres.NewBranchRepository(db), postgres.NewTenantRepository(db),
		postgres.NewAuditRepository(db), logger.NewNop())
	svc.SetSecretFingerprinter(vulnerability.NewSecretFingerprinter([]byte("golden-corpus-server-secret-0123456789")))
	return &goldenRig{r: r, svc: svc}
}

func (g *goldenRig) ingest(t *testing.T, tn v2Tenant, file goldenFile, tool string, f ctis.Finding) {
	t.Helper()
	tid := tn.tenant
	agt := &sensor.Sensor{ID: tn.sensor, TenantID: &tid, Type: sensor.SensorTypeWorker, Status: sensor.SensorStatusActive}
	value := file.Asset.Value
	if file.Asset.Type != ctis.AssetTypeRepository {
		value = tn.tenant.String()[:8] + "." + value
	}
	f.AssetRef = "a"
	rep := &ctis.Report{Version: "1.0", Tool: &ctis.Tool{Name: tool},
		Metadata: ctis.ReportMetadata{ID: shared.NewID().String(), Timestamp: time.Now().UTC()},
		Assets:   []ctis.Asset{{ID: "a", Type: file.Asset.Type, Value: value}},
		Findings: []ctis.Finding{f}}
	out, err := g.svc.Ingest(context.Background(), agt, ingest.Input{Report: rep})
	if err != nil || len(out.Errors) > 0 {
		t.Fatalf("ingest: %v %v", err, out.Errors)
	}
}

type goldenRow struct {
	id, fingerprint, status, asset string
	version                        int
	cve                            string
}

func (g *goldenRig) rows(t *testing.T, tn v2Tenant) []goldenRow {
	t.Helper()
	rs, err := g.r.db.Query(`SELECT id, fingerprint, status, fingerprint_version, COALESCE(cve_id, ''), asset_id
		FROM findings WHERE tenant_id = $1 AND status <> 'duplicate' ORDER BY cve_id, created_at`, tn.tenant.String())
	if err != nil {
		t.Fatal(err)
	}
	defer rs.Close()
	var out []goldenRow
	for rs.Next() {
		var x goldenRow
		if err := rs.Scan(&x.id, &x.fingerprint, &x.status, &x.version, &x.cve, &x.asset); err != nil {
			t.Fatal(err)
		}
		out = append(out, x)
	}
	if err := rs.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func ids(rows []goldenRow) map[string]bool {
	m := make(map[string]bool, len(rows))
	for _, r := range rows {
		m[r.id] = true
	}
	return m
}

func loadGolden(t *testing.T) map[string]goldenFile {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join("testdata", "dedup", "*.json"))
	if err != nil || len(paths) == 0 {
		t.Fatalf("no golden corpus: %v", err)
	}
	out := map[string]goldenFile{}
	for _, p := range paths {
		raw, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		var f goldenFile
		if err := json.Unmarshal(raw, &f); err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		out[strings.TrimSuffix(filepath.Base(p), ".json")] = f
	}
	return out
}

func sortedKeys(m map[string]goldenFile) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func TestDedupGolden_RescansMapToTheSameFinding(t *testing.T) {
	g := newGoldenRig(t)
	corpus := loadGolden(t)
	for _, name := range sortedKeys(corpus) {
		file := corpus[name]
		for _, c := range file.Cases {
			t.Run(name+"/"+c.Name, func(t *testing.T) {
				tn := g.r.newTenant(file.Tool)
				g.ingest(t, tn, file, file.Tool, c.Before)
				before := g.rows(t, tn)
				if len(before) == 0 {
					t.Fatal("the first result created no finding")
				}
				afterTool := file.Tool
				if c.AfterTool != "" {
					afterTool = c.AfterTool
				}
				g.ingest(t, tn, file, afterTool, c.After)
				after := g.rows(t, tn)
				switch c.Expect {
				case "same":
					if len(after) != len(before) {
						t.Fatalf("expected the same finding: %d findings became %d", len(before), len(after))
					}
				case "different":
					if len(after) != len(before)+1 {
						t.Fatalf("expected a different finding: %d findings became %d", len(before), len(after))
					}
				default:
					t.Fatalf("bad expect %q", c.Expect)
				}
				for _, r := range after {
					if r.version != vulnerability.IdentityVersion {
						t.Fatalf("finding keyed with version %d, want %d", r.version, vulnerability.IdentityVersion)
					}
				}
			})
		}
	}
}

func TestDedupGolden_VersionOneFindingsAreReKeyedWithTheirTriage(t *testing.T) {
	g := newGoldenRig(t)
	corpus := loadGolden(t)
	for _, name := range sortedKeys(corpus) {
		file := corpus[name]
		for _, c := range file.Cases {
			t.Run(name+"/"+c.Name, func(t *testing.T) {
				tn := g.r.newTenant(file.Tool)
				g.ingest(t, tn, file, file.Tool, c.Before)
				rows := g.rows(t, tn)
				// Before version 2 a grouped multi-CVE plugin was ONE
				// finding, keyed on its lowest CVE: keep that one row.
				for _, extra := range rows[1:] {
					if _, err := g.r.db.Exec(`DELETE FROM findings WHERE id = $1`, extra.id); err != nil {
						t.Fatal(err)
					}
				}
				row := rows[0]
				asset, err := shared.IDFromString(row.asset)
				if err != nil {
					t.Fatal(err)
				}
				before := c.Before
				v1 := ingest.VersionOneFingerprint(asset, &before, &ctis.Tool{Name: file.Tool})
				if _, err := g.r.db.Exec(`UPDATE findings SET fingerprint = $2, fingerprint_version = 1, identity_key = NULL,
					status = 'false_positive', resolution = 'false_positive' WHERE id = $1`, row.id, v1); err != nil {
					t.Fatal(err)
				}
				// A row written before version 2 never had a version-2 alias.
				if _, err := g.r.db.Exec(`DELETE FROM finding_fingerprints WHERE finding_id = $1 AND fingerprint <> $2`, row.id, v1); err != nil {
					t.Fatal(err)
				}

				// The same result again, after the upgrade.
				g.ingest(t, tn, file, file.Tool, c.Before)
				again := g.rows(t, tn)
				if !ids(again)[row.id] {
					t.Fatal("the version-1 finding is gone")
				}
				var got goldenRow
				for _, r := range again {
					if r.id == row.id {
						got = r
					}
				}
				if got.version != vulnerability.IdentityVersion || got.fingerprint == v1 {
					t.Fatalf("not re-keyed: version %d, fingerprint %s", got.version, got.fingerprint)
				}
				if got.status != "false_positive" {
					t.Fatalf("status = %s, want false_positive (triage lost)", got.status)
				}
				if len(again) != len(rows) {
					t.Fatalf("%d findings after re-ingest, want %d (a duplicate of the version-1 finding appeared)", len(again), len(rows))
				}
				if got := aliasOwner(t, g.r.db, tn.tenant, v1); got != row.id {
					t.Fatalf("the version-1 key belongs to %q, want the re-keyed finding %s", got, row.id)
				}
			})
		}
	}
}
