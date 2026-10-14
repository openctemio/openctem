package integration

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// The SAST engine moves from semgrep to opengrep (research/132). Findings a
// semgrep run stored must be the findings the first opengrep run reports:
// same rows, triage kept, re-keyed to the version-2 identity, no duplicate
// and nothing left behind to be auto-resolved. The fixtures are the CTIS the
// ctis importer writes for the same tree and rules from each engine.

type engineFixture struct {
	Semgrep  []ctis.Finding `json:"semgrep"`
	Opengrep []ctis.Finding `json:"opengrep"`
}

func loadEngineFixture(t *testing.T) engineFixture {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "engine", "semgrep-to-opengrep.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fx engineFixture
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatal(err)
	}
	if len(fx.Semgrep) == 0 || len(fx.Semgrep) != len(fx.Opengrep) {
		t.Fatalf("fixture: %d semgrep, %d opengrep findings", len(fx.Semgrep), len(fx.Opengrep))
	}
	return fx
}

func (g *goldenRig) ingestAll(t *testing.T, tn v2Tenant, tool string, fs []ctis.Finding) {
	t.Helper()
	tid := tn.tenant
	agt := &sensor.Sensor{ID: tn.sensor, TenantID: &tid, Type: sensor.SensorTypeWorker, Status: sensor.SensorStatusActive}
	cp := make([]ctis.Finding, len(fs))
	for i := range fs {
		cp[i] = fs[i]
		cp[i].AssetRef = "a"
	}
	rep := &ctis.Report{Version: "1.0", Tool: &ctis.Tool{Name: tool, Capabilities: []string{"sast"}},
		Metadata: ctis.ReportMetadata{ID: shared.NewID().String(), Timestamp: time.Now().UTC()},
		Assets:   []ctis.Asset{{ID: "a", Type: ctis.AssetTypeRepository, Value: "github.com/acme/shop"}},
		Findings: cp}
	out, err := g.svc.Ingest(context.Background(), agt, ingest.Input{Report: rep})
	if err != nil || len(out.Errors) > 0 {
		t.Fatalf("ingest %s: %v %v", tool, err, out.Errors)
	}
}

func TestSASTEngineChange_SemgrepFindingsCarryOverToOpengrep(t *testing.T) {
	fx := loadEngineFixture(t)
	g := newGoldenRig(t)
	tn := g.r.newTenant("semgrep")

	g.ingestAll(t, tn, "semgrep", fx.Semgrep)
	before := g.rows(t, tn)
	if len(before) != len(fx.Semgrep) {
		t.Fatalf("semgrep stored %d findings, want %d", len(before), len(fx.Semgrep))
	}
	// Triage one of them, as a tenant would have.
	triaged := before[0].id
	if _, err := g.r.db.Exec(`UPDATE findings SET status = 'false_positive', resolution = 'false_positive' WHERE id = $1`, triaged); err != nil {
		t.Fatal(err)
	}

	g.ingestAll(t, tn, "opengrep", fx.Opengrep)
	after := g.rows(t, tn)
	if len(after) != len(before) {
		t.Fatalf("the engine change duplicated findings: %d became %d", len(before), len(after))
	}
	was := ids(before)
	for _, r := range after {
		if !was[r.id] {
			t.Fatalf("finding %s is new: the opengrep result did not find the semgrep finding", r.id)
		}
		if r.version != vulnerability.IdentityVersion {
			t.Errorf("finding %s keyed with version %d, want %d (re-keyed on the opengrep sighting)", r.id, r.version, vulnerability.IdentityVersion)
		}
		if r.id == triaged && r.status != "false_positive" {
			t.Errorf("triage lost: status %q", r.status)
		}
	}

	// A second opengrep run maps to the same findings again.
	g.ingestAll(t, tn, "opengrep", fx.Opengrep)
	if again := g.rows(t, tn); len(again) != len(before) {
		t.Fatalf("second opengrep run: %d findings, want %d", len(again), len(before))
	}
}

// A result of the same rule on another line is another finding: the
// carry-over never merges unrelated results.
func TestSASTEngineChange_OtherLineIsAnotherFinding(t *testing.T) {
	fx := loadEngineFixture(t)
	g := newGoldenRig(t)
	tn := g.r.newTenant("semgrep")
	g.ingestAll(t, tn, "semgrep", fx.Semgrep[:1])

	moved := fx.Opengrep[0]
	loc := *moved.Location
	loc.StartLine += 10
	loc.EndLine = loc.StartLine
	loc.Snippet = "    os.system(other)"
	moved.Location = &loc
	moved.Fingerprint = "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
	moved.PartialFingerprints = map[string]string{"matchBasedId/v1": "ffff_0"}
	g.ingestAll(t, tn, "opengrep", []ctis.Finding{moved})
	if rows := g.rows(t, tn); len(rows) != 2 {
		t.Fatalf("a result on another line merged into the semgrep finding: %d findings", len(rows))
	}
}
