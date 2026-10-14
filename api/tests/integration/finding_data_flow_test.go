package integration

// Data flows (taint traces) at ingest: a new finding gets its trace, a
// re-scan with the same trace leaves the rows alone, a changed trace replaces
// them in one transaction, a report without a trace keeps the stored one, the
// per-finding caps hold, the trace never changes the finding's identity, and
// no read or write reaches another tenant's finding.

import (
	"context"
	"fmt"
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

func flowReport(repo string, df *ctis.DataFlow) *ctis.Report {
	return &ctis.Report{Version: "1.0", Tool: &ctis.Tool{Name: "semgrep", Version: "1.90.0"},
		Metadata: ctis.ReportMetadata{ID: shared.NewID().String(), Timestamp: time.Now().UTC()},
		Assets:   []ctis.Asset{{ID: "r", Type: ctis.AssetTypeRepository, Value: repo}},
		Findings: []ctis.Finding{{Type: ctis.FindingTypeVulnerability, Title: "SQL injection", Severity: ctis.SeverityHigh,
			RuleID: "js.sqli", AssetRef: "r",
			Location: &ctis.FindingLocation{Path: "src/db.js", StartLine: 22, Snippet: "db.query(q)"},
			DataFlow: df}}}
}

func flowOf(sourcePath string, steps int) *ctis.DataFlow {
	df := &ctis.DataFlow{Sources: []ctis.DataFlowLocation{{Path: sourcePath, Line: 3, Content: "const id = req.query.id", Index: 0}}}
	for i := 1; i < steps-1; i++ {
		df.Intermediates = append(df.Intermediates, ctis.DataFlowLocation{Path: "src/db.js", Line: 10 + i, Content: fmt.Sprintf("q%d", i), Index: i + 1})
	}
	df.Sinks = []ctis.DataFlowLocation{{Path: "src/db.js", Line: 22, Content: "db.query(q)", Index: steps}}
	df.Sanitizers = []ctis.DataFlowLocation{{Path: "src/db.js", Line: 5, Content: "escape(id)", Index: 1}}
	return df
}

type storedFlow struct {
	findingID, fingerprint, flowID, hash string
	steps                                int
	sourcePath                           string
}

func storedFlowOf(t *testing.T, r *v2Rig, tenant shared.ID) storedFlow {
	t.Helper()
	var s storedFlow
	if err := r.db.QueryRow(`SELECT id, fingerprint FROM findings WHERE tenant_id = $1`, tenant.String()).Scan(&s.findingID, &s.fingerprint); err != nil {
		t.Fatalf("one finding: %v", err)
	}
	var flows int
	_ = r.db.QueryRow(`SELECT count(*) FROM finding_data_flows WHERE finding_id = $1`, s.findingID).Scan(&flows)
	if flows == 0 {
		return s
	}
	if flows != 1 {
		t.Fatalf("finding has %d data flows, want 1", flows)
	}
	if err := r.db.QueryRow(`SELECT df.id, coalesce(df.trace_hash, ''),
			(SELECT count(*) FROM finding_flow_locations fl WHERE fl.data_flow_id = df.id),
			coalesce((SELECT file_path FROM finding_flow_locations fl WHERE fl.data_flow_id = df.id AND location_type = 'source'), '')
		FROM finding_data_flows df WHERE df.finding_id = $1`, s.findingID).Scan(&s.flowID, &s.hash, &s.steps, &s.sourcePath); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestFindingDataFlows_ReplacedOnlyWhenChanged(t *testing.T) {
	r := newV2Rig(t, ingest.DefaultBlindingGuard())
	db := &postgres.DB{DB: r.db}
	flows := postgres.NewDataFlowRepository(db)
	svc := ingest.NewService(
		postgres.NewAssetRepository(db), postgres.NewFindingRepository(db),
		postgres.NewVulnerabilityRepository(db), postgres.NewComponentRepository(db),
		postgres.NewSensorRepository(db), postgres.NewBranchRepository(db), postgres.NewTenantRepository(db),
		postgres.NewAuditRepository(db), logger.NewNop())
	svc.SetToolFacts(integrationTools)
	svc.SetDataFlowRepository(flows)
	ingestAs := func(tn v2Tenant, rep *ctis.Report) {
		t.Helper()
		tid := tn.tenant
		agt := &sensor.Sensor{ID: tn.sensor, TenantID: &tid, Type: sensor.SensorTypeWorker, Status: sensor.SensorStatusActive}
		if _, err := svc.Ingest(context.Background(), agt, ingest.Input{Report: rep}); err != nil {
			t.Fatal(err)
		}
	}
	tn := r.newTenant("semgrep")
	other := r.newTenant("semgrep")
	repo := "github.com/acme/" + tn.tenant.String()[:8]

	// A finding first seen without a trace: no rows. Its identity is the
	// baseline for every later sighting.
	ingestAs(tn, flowReport(repo, nil))
	base := storedFlowOf(t, r, tn.tenant)
	if base.flowID != "" {
		t.Fatalf("a finding without a trace has data flows: %+v", base)
	}

	// The same finding with a trace: same finding, same fingerprint, the
	// trace stored in step order with the sanitizer.
	ingestAs(tn, flowReport(repo, flowOf("src/routes.js", 4)))
	first := storedFlowOf(t, r, tn.tenant)
	if first.findingID != base.findingID || first.fingerprint != base.fingerprint {
		t.Fatalf("the trace changed the finding's identity: %+v vs %+v", first, base)
	}
	if first.flowID == "" || first.steps != 5 || first.sourcePath != "src/routes.js" || len(first.hash) != 64 {
		t.Fatalf("first trace stored %+v", first)
	}
	var order string
	_ = r.db.QueryRow(`SELECT string_agg(location_type, ',' ORDER BY step_index) FROM finding_flow_locations WHERE data_flow_id = $1`, first.flowID).Scan(&order)
	if order != "source,sanitizer,intermediate,intermediate,sink" {
		t.Errorf("step order %q", order)
	}

	// The same trace again: nothing rewritten (same row id).
	ingestAs(tn, flowReport(repo, flowOf("src/routes.js", 4)))
	if again := storedFlowOf(t, r, tn.tenant); again.flowID != first.flowID || again.hash != first.hash {
		t.Fatalf("an unchanged trace was rewritten: %+v -> %+v", first, again)
	}

	// A changed path: the trace is replaced, still one flow, with the
	// commit it was reported for.
	changedRep := flowReport(repo, flowOf("src/api/orders.js", 4))
	changedRep.Findings[0].Location.CommitSHA = "0123456789abcdef0123456789abcdef01234567"
	ingestAs(tn, changedRep)
	changed := storedFlowOf(t, r, tn.tenant)
	if changed.flowID == first.flowID || changed.sourcePath != "src/api/orders.js" || changed.hash == first.hash || changed.steps != 5 {
		t.Fatalf("a changed trace was not replaced: %+v -> %+v", first, changed)
	}
	if changed.fingerprint != base.fingerprint {
		t.Fatalf("fingerprint changed with the trace: %s -> %s", base.fingerprint, changed.fingerprint)
	}
	var orphans int
	_ = r.db.QueryRow(`SELECT count(*) FROM finding_flow_locations WHERE data_flow_id = $1`, first.flowID).Scan(&orphans)
	if orphans != 0 {
		t.Errorf("%d locations of the replaced flow remain", orphans)
	}

	var commit string
	_ = r.db.QueryRow(`SELECT coalesce(commit_sha, '') FROM finding_data_flows WHERE id = $1`, changed.flowID).Scan(&commit)
	if commit != "0123456789abcdef0123456789abcdef01234567" {
		t.Errorf("trace commit %q", commit)
	}

	// A report without a trace keeps the stored one.
	ingestAs(tn, flowReport(repo, nil))
	if kept := storedFlowOf(t, r, tn.tenant); kept.flowID != changed.flowID {
		t.Fatalf("a report without a trace dropped the stored one: %+v", kept)
	}

	// The per-flow cap: a 300-step trace stores MaxLocationsPerDataFlow steps.
	long := flowOf("src/routes.js", 300)
	long.Sanitizers = nil
	ingestAs(tn, flowReport(repo, long))
	if capped := storedFlowOf(t, r, tn.tenant); capped.steps != vulnerability.MaxLocationsPerDataFlow {
		t.Fatalf("stored %d steps, want %d", capped.steps, vulnerability.MaxLocationsPerDataFlow)
	}

	// Another tenant's ingest of the same repository and trace touches
	// only its own finding.
	before := storedFlowOf(t, r, tn.tenant)
	ingestAs(other, flowReport(repo, flowOf("src/other.js", 3)))
	if after := storedFlowOf(t, r, tn.tenant); after.flowID != before.flowID || after.hash != before.hash {
		t.Fatalf("another tenant's ingest changed this tenant's trace")
	}
	theirs := storedFlowOf(t, r, other.tenant)
	if theirs.sourcePath != "src/other.js" {
		t.Fatalf("other tenant stored %+v", theirs)
	}

	ctx := context.Background()
	// Repository, cross-tenant write: this tenant's fingerprint sent as
	// another tenant resolves no finding and changes nothing.
	trace, _ := vulnerability.NewFindingTrace(before.fingerprint, "", []vulnerability.DataFlow{{Steps: []vulnerability.DataFlowStep{{LocationType: "sink", Location: &vulnerability.FindingLocation{Path: "evil.js"}}}}})
	stranger := shared.NewID()
	if n, err := flows.ReplaceDataFlows(ctx, stranger, []vulnerability.FindingTrace{trace}); err != nil || n != 0 {
		t.Fatalf("a write as another tenant replaced %d (%v)", n, err)
	}
	if after := storedFlowOf(t, r, tn.tenant); after.flowID != before.flowID {
		t.Fatal("a write as another tenant replaced this tenant's trace")
	}
	// Repository, cross-tenant read: nothing.
	fid := shared.MustIDFromString(before.findingID)
	if got, locs, err := flows.GetDataFlowsWithLocations(ctx, other.tenant, fid); err != nil || len(got) != 0 || len(locs) != 0 {
		t.Fatalf("cross-tenant read returned %d flows (%v)", len(got), err)
	}
	got, locs, err := flows.GetDataFlowsWithLocations(ctx, tn.tenant, fid)
	if err != nil || len(got) != 1 || len(locs[got[0].ID().String()]) != vulnerability.MaxLocationsPerDataFlow {
		t.Fatalf("own read: %d flows, %v", len(got), err)
	}
}
