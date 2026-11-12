package refingerprintcmd

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"testing"

	"github.com/openctemio/ctis/v2/importer"

	"github.com/openctemio/openctem/server/internal/app/exposurebridge"
	"github.com/openctemio/openctem/server/internal/app/ingest"
	"github.com/openctemio/openctem/server/internal/infra/postgres"
	"github.com/openctemio/openctem/server/internal/testdb"
	"github.com/openctemio/openctem/server/pkg/domain/sensor"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/tenant"
	"github.com/openctemio/openctem/server/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/server/pkg/logger"
)

// infoFixture is a real nuclei v3.11.1 run (internal/app/ingest/testdata):
// 12 info matches (2 tech-detect, 10 header matchers) and a medium and a
// high finding, on one web origin. Filed as findings (as before info
// matches became exposures) the info matches are two findings, since the
// finding identity has no matcher: tech-detect and
// http-missing-security-headers, each keeping its last matcher.
const infoFixture = "../../app/ingest/testdata/nuclei_info_matches.jsonl"

type infoEnv struct {
	t      *testing.T
	db     *sql.DB
	pdb    *postgres.DB
	plain  *ingest.Service // files info matches as findings (as before)
	routed *ingest.Service // files them as exposures (as now)
}

func newInfoEnv(t *testing.T) *infoEnv {
	t.Helper()
	url := testdb.URL()
	if url == "" {
		t.Skip("DATABASE_URL not set")
	}
	db, err := sql.Open("postgres", url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.PingContext(context.Background()); err != nil {
		testdb.Skipf(t, "database unreachable: %v", err)
	}
	pdb := &postgres.DB{DB: db}
	log := logger.NewNop()
	newIngest := func() *ingest.Service {
		return ingest.NewService(postgres.NewAssetRepository(pdb), postgres.NewFindingRepository(pdb),
			postgres.NewVulnerabilityRepository(pdb), postgres.NewComponentRepository(pdb),
			postgres.NewSensorRepository(pdb), postgres.NewBranchRepository(pdb), postgres.NewTenantRepository(pdb),
			postgres.NewAuditRepository(pdb), log)
	}
	env := &infoEnv{t: t, db: db, pdb: pdb, plain: newIngest(), routed: newIngest()}
	env.routed.SetTemplateMatchProjector(exposurebridge.NewBridge(postgres.NewExposureRepository(pdb),
		postgres.NewExposureStateHistoryRepository(pdb), log))
	return env
}

func (e *infoEnv) tenant(asFindings bool) shared.ID {
	e.t.Helper()
	tn, err := tenant.NewTenant("info-reclassify", "info-reclassify-"+shared.NewID().String()[:18], shared.NewID().String())
	if err != nil {
		e.t.Fatal(err)
	}
	if asFindings {
		st := tn.TypedSettings()
		st.EASM.InfoMatchesAsFindings = true
		if err := tn.UpdateSettings(st); err != nil {
			e.t.Fatal(err)
		}
	}
	settings, err := json.Marshal(tn.Settings())
	if err != nil {
		e.t.Fatal(err)
	}
	e.exec(`INSERT INTO tenants (id, name, slug, settings) VALUES ($1, $2, $3, $4)`, tn.ID().String(), tn.Name(), tn.Slug(), settings)
	id := tn.ID()
	e.t.Cleanup(func() {
		ctx := context.Background()
		for _, q := range []string{`DELETE FROM exposure_events WHERE tenant_id = $1`, `DELETE FROM findings WHERE tenant_id = $1`,
			`DELETE FROM assets WHERE tenant_id = $1`, `DELETE FROM audit_logs WHERE tenant_id = $1`, `DELETE FROM tenants WHERE id = $1`} {
			_, _ = e.db.ExecContext(ctx, q, id.String())
		}
	})
	return id
}

// ingestFixture ingests the nuclei run into the tenant through svc.
func (e *infoEnv) ingestFixture(svc *ingest.Service, tenantID shared.ID) {
	e.t.Helper()
	f, err := os.Open(infoFixture)
	if err != nil {
		e.t.Fatal(err)
	}
	defer f.Close()
	res, err := importer.Parse(context.Background(), f, importer.Options{Format: importer.FormatNuclei})
	if err != nil {
		e.t.Fatal(err)
	}
	agt := &sensor.Sensor{TenantID: &tenantID, Status: sensor.SensorStatusActive}
	if _, err := svc.Ingest(context.Background(), agt, ingest.Input{Report: res.Report}); err != nil {
		e.t.Fatal(err)
	}
}

func (e *infoEnv) count(q string, args ...any) int {
	e.t.Helper()
	var n int
	if err := e.db.QueryRowContext(context.Background(), q, args...).Scan(&n); err != nil {
		e.t.Fatalf("%s: %v", q, err)
	}
	return n
}

func (e *infoEnv) exec(q string, args ...any) {
	e.t.Helper()
	if _, err := e.db.ExecContext(context.Background(), q, args...); err != nil {
		e.t.Fatalf("%s: %v", q, err)
	}
}

// The stored informational findings of a template scanner move to
// exposures exactly as ingest moves a new match: the same exposure event (a
// later scan bumps it, never files a second one), the finding resolved as
// reclassified_exposure and never counted as fixed, severity none mapped to
// info, a timeline entry and one audit entry. Held findings, other tenants
// and an organization that files info matches as findings are untouched;
// a dry run changes nothing; a second run changes nothing; -down undoes it.
func TestInfoExposures_MovesStoredInfoFindings_DB(t *testing.T) {
	e := newInfoEnv(t)
	ctx := context.Background()
	a, held, b, keep := e.tenant(false), e.tenant(false), e.tenant(false), e.tenant(true)
	for _, tn := range []shared.ID{a, held, b, keep} {
		e.ingestFixture(e.plain, tn)
	}
	infoOpen := `SELECT COUNT(*) FROM findings WHERE tenant_id = $1 AND severity IN ('info', 'none') AND status IN ('new', 'confirmed')`
	if n := e.count(infoOpen, a); n != 2 {
		t.Fatalf("fixture: %d open info findings, want 2", n)
	}
	// Findings filed before info became info were none.
	e.exec(`UPDATE findings SET severity = 'none' WHERE tenant_id = $1 AND rule_id = 'tech-detect'`, a)
	// In tenant held, one is on a ticket.
	e.exec(`UPDATE findings SET work_item_uris = ARRAY['https://tracker.example.com/T-1'] WHERE tenant_id = $1 AND rule_id = 'tech-detect'`, held)

	repo := postgres.NewInfoReclassifyRepository(e.pdb)
	tenants := postgres.NewTenantRepository(e.pdb)
	dry, err := ReclassifyInfoTenant(ctx, repo, tenants, a, false, 1)
	if err != nil || dry.Scanned != 2 || dry.Moved != 2 || dry.Held != 0 || dry.Invalid != 0 {
		t.Fatalf("dry run = %+v, %v", dry, err)
	}
	if n := e.count(infoOpen, a); n != 2 || e.count(`SELECT COUNT(*) FROM exposure_events WHERE tenant_id = $1`, a) != 0 {
		t.Fatal("the dry run changed something")
	}

	if code := runInfoExposures(ctx, e.db, a.String(), true, false, true, 1); code != 0 {
		t.Fatalf("apply exit %d", code)
	}
	moved := `SELECT COUNT(*) FROM findings WHERE tenant_id = $1 AND status = 'resolved'
		AND closure_reason = 'reclassified_exposure' AND verification = 'none' AND severity = 'info' AND resolved_by IS NULL`
	if n := e.count(moved, a); n != 2 {
		t.Fatalf("moved %d, want 2", n)
	}
	if n := e.count(`SELECT COUNT(*) FROM findings WHERE tenant_id = $1 AND severity IN ('medium', 'high') AND status = 'new'`, a); n != 2 {
		t.Fatalf("real findings changed: %d open, want 2", n)
	}
	if n := e.count(`SELECT COUNT(*) FROM findings f WHERE f.tenant_id = $1 AND `+vulnerability.RemediatedSQL("f"), a); n != 0 {
		t.Fatalf("%d moved findings count as remediated", n)
	}
	if n := e.count(`SELECT COUNT(*) FROM exposure_events WHERE tenant_id = $1 AND source = 'template_scan'
		AND severity = 'info' AND details ? 'reclassified_from_finding'`, a); n != 2 {
		t.Fatalf("%d exposure events, want 2", n)
	}
	if n := e.count(`SELECT COUNT(*) FROM finding_activities WHERE tenant_id = $1 AND source = 'info_reclassify'
		AND changes->>'new_status' = 'resolved' AND changes ? 'exposure_event_id' AND changes ? 'previous_severity'`, a); n != 2 {
		t.Fatalf("%d timeline entries, want 2", n)
	}
	auditQ := `SELECT COUNT(*) FROM audit_logs WHERE tenant_id = $1 AND action = 'findings.reclassified'`
	if n := e.count(auditQ, a); n != 1 {
		t.Fatalf("%d audit entries, want 1", n)
	}
	for _, other := range []shared.ID{held, b, keep} {
		if n := e.count(infoOpen, other); n != 2 {
			t.Fatalf("another tenant changed: %d open info findings", n)
		}
	}

	// A finding on a ticket is held; the other one moves.
	rep, err := ReclassifyInfoTenant(ctx, repo, tenants, held, true, 10)
	if err != nil || rep.Moved != 1 || rep.Held != 1 {
		t.Fatalf("held tenant = %+v, %v", rep, err)
	}
	if n := e.count(`SELECT COUNT(*) FROM findings WHERE tenant_id = $1 AND rule_id = 'tech-detect' AND status = 'new'`, held); n != 1 {
		t.Fatal("the finding on a ticket was moved")
	}
	// An organization that files info matches as findings is skipped even
	// when named.
	if rep, err := ReclassifyInfoTenant(ctx, repo, tenants, keep, true, 5); err != nil || !rep.Skipped || rep.Moved != 0 {
		t.Fatalf("setting tenant = %+v, %v", rep, err)
	}
	if n := e.count(infoOpen, keep); n != 2 {
		t.Fatal("the setting tenant changed")
	}

	// Idempotent.
	if code := runInfoExposures(ctx, e.db, a.String(), true, false, true, 5); code != 0 {
		t.Fatalf("second apply exit %d", code)
	}
	if e.count(moved, a) != 2 || e.count(`SELECT COUNT(*) FROM exposure_events WHERE tenant_id = $1`, a) != 2 || e.count(auditQ, a) != 1 {
		t.Fatal("a second run changed something")
	}

	// Down: status and severity back, the untouched events removed.
	if code := runInfoExposures(ctx, e.db, a.String(), true, true, true, 1); code != 0 {
		t.Fatalf("down exit %d", code)
	}
	if n := e.count(infoOpen, a); n != 2 {
		t.Fatalf("down reopened to %d open info findings, want 2", n)
	}
	if n := e.count(`SELECT COUNT(*) FROM findings WHERE tenant_id = $1 AND severity = 'none' AND status = 'new'`, a); n != 1 {
		t.Fatalf("down restored %d none severities, want 1", n)
	}
	if n := e.count(`SELECT COUNT(*) FROM exposure_events WHERE tenant_id = $1`, a); n != 0 {
		t.Fatalf("down left %d events", n)
	}
	if n := e.count(auditQ, a); n != 2 {
		t.Fatalf("down wrote no audit entry (%d)", n)
	}

	// Apply again, then the next scan. Its twelve info matches are not all
	// exposures any more: eight map to asset facts (technologies, header
	// posture; tech-detect and the missing-header matchers among them) and
	// four the mapping does not name are filed as exposures. Nothing is
	// dropped: twelve matches = four new exposure events + eight facts. The
	// two moved events stay as the history of what was filed before; the
	// next scan no longer bumps them, since their matches are facts now.
	// No moved finding reopens.
	if code := runInfoExposures(ctx, e.db, a.String(), true, false, true, 50); code != 0 {
		t.Fatalf("re-apply exit %d", code)
	}
	e.ingestFixture(e.routed, a)
	if n := e.count(`SELECT COUNT(*) FROM exposure_events WHERE tenant_id = $1`, a); n != 6 {
		t.Fatalf("after the next scan %d events, want 6 (2 moved ones kept, 4 unmapped matchers added)", n)
	}
	if n := e.count(`SELECT COUNT(*) FROM exposure_events WHERE tenant_id = $1 AND details ? 'reclassified_from_finding'
		AND last_seen_at > first_seen_at`, a); n != 0 {
		t.Fatalf("%d moved events bumped by the next scan, want 0 (their matches are asset facts now)", n)
	}
	// The eight facts are on the asset: the header posture its missing-header
	// matches prove (eight matchers become posture keys, not events).
	if n := e.count(`SELECT COUNT(*) FROM assets WHERE tenant_id = $1 AND properties->'http_posture'->>'hsts' = 'false'
		AND properties->'http_posture'->>'csp' = 'false'`, a); n != 1 {
		t.Fatalf("%d assets carry the header posture of the info matches, want 1", n)
	}
	if n := e.count(moved, a); n != 2 {
		t.Fatalf("after the next scan %d still moved, want 2", n)
	}
}
