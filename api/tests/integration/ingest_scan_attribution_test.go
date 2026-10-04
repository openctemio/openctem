package integration

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/internal/app/easm"
	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// tenant_scanned evidence through the real ingest (RFC-036 O8): only a
// report bound to a command of the tenant's sensor stamps it, only on assets
// the report created or its command covers, it raises an automatic
// needs_review record to confirmed, and it never overrides a person.
func TestIngest_TenantScannedAttribution(t *testing.T) {
	r := newV2Rig(t, ingest.DefaultBlindingGuard())
	tn := r.newTenant("subfinder")
	db := &postgres.DB{DB: r.db}
	ctx := context.Background()
	attr := postgres.NewAttributionRepository(db)
	svc := ingest.NewService(
		postgres.NewAssetRepository(db), postgres.NewFindingRepository(db),
		postgres.NewVulnerabilityRepository(db), postgres.NewComponentRepository(db),
		postgres.NewSensorRepository(db), postgres.NewBranchRepository(db), postgres.NewTenantRepository(db),
		postgres.NewAuditRepository(db), logger.NewNop())
	svc.SetScanAttributionStamper(easm.NewScanStamper(attr))
	tid := tn.tenant
	agt := &sensor.Sensor{ID: tn.sensor, TenantID: &tid, Type: sensor.SensorTypeWorker, Status: sensor.SensorStatusActive}

	run := func(bind ingest.Binding, hosts ...string) {
		t.Helper()
		assets := make([]ctis.Asset, 0, len(hosts))
		for i, h := range hosts {
			assets = append(assets, ctis.Asset{ID: string(rune('a' + i)), Type: ctis.AssetTypeHost, Value: h})
		}
		rep := &ctis.Report{Version: "1.0", Tool: &ctis.Tool{Name: "subfinder"}, Assets: assets,
			Metadata: ctis.ReportMetadata{ID: "rep-1", Timestamp: time.Now().UTC()}}
		out, err := svc.Ingest(ctx, agt, ingest.Input{Report: rep, Options: ingest.Options{Binding: bind}})
		if err != nil || len(out.Errors) > 0 {
			t.Fatalf("Ingest: %v %v", err, out.Errors)
		}
	}
	idOf := func(name string) string {
		t.Helper()
		var id string
		if err := r.db.QueryRowContext(ctx, `SELECT id FROM assets WHERE tenant_id = $1 AND name = $2`, tid.String(), name).Scan(&id); err != nil {
			t.Fatalf("asset %s: %v", name, err)
		}
		return id
	}
	evidence := func(name string) (n int, cmd string) {
		t.Helper()
		_ = r.db.QueryRowContext(ctx, `SELECT count(*), coalesce(max(observed->>'command_id'), '') FROM easm_evidence
			WHERE tenant_id = $1 AND asset_id = $2 AND rule = 'tenant_scanned'`, tid.String(), idOf(name)).Scan(&n, &cmd)
		return n, cmd
	}
	state := func(name string) attribution.State {
		t.Helper()
		recs, err := attr.Records(ctx, tid, []string{idOf(name)})
		if err != nil {
			t.Fatal(err)
		}
		return recs[idOf(name)].State
	}

	// A CT name waiting for review and one a person rejected.
	run(ingest.Binding{}, "ct.example.com", "gone.example.com")
	if err := attr.SaveAutomatic(ctx, tid, idOf("ct.example.com"), attribution.Decision{State: attribution.StateNeedsReview, Confidence: 85, Reason: attribution.RuleAssertedRoot}); err != nil {
		t.Fatal(err)
	}
	if err := attr.UpsertEvidence(ctx, tid, []attribution.Evidence{{AssetID: idOf("ct.example.com"), Rule: attribution.RuleAssertedRoot, Technique: "cert_transparency", Source: "crt.sh", Weight: 0.85}}); err != nil {
		t.Fatal(err)
	}
	if _, err := attr.SaveDecision(ctx, tid, idOf("gone.example.com"), attribution.StateRejected, ""); err != nil {
		t.Fatal(err)
	}
	if n, _ := evidence("ct.example.com"); n != 0 {
		t.Fatal("an unsolicited report stamped tenant_scanned")
	}

	// A command for new.example.com also reports ct.example.com, outside its
	// targets: the new asset is stamped, the CT name is not raised.
	cmd := shared.NewID()
	run(ingest.Binding{Kind: ingest.BindingCommand, CommandID: &cmd, Targets: []string{"new.example.com"}},
		"new.example.com", "ct.example.com")
	if n, c := evidence("new.example.com"); n != 1 || c != cmd.String() {
		t.Fatalf("created asset: %d rows, command %q", n, c)
	}
	if n, _ := evidence("ct.example.com"); n != 0 || state("ct.example.com") != attribution.StateNeedsReview {
		t.Fatal("a command raised an asset outside its targets")
	}

	// A command that targets the CT name confirms it (asserted root + tenant
	// scanned) but leaves the rejected one rejected.
	cmd2 := shared.NewID()
	run(ingest.Binding{Kind: ingest.BindingCommand, CommandID: &cmd2, Targets: []string{"ct.example.com", "gone.example.com"}},
		"ct.example.com", "gone.example.com")
	if got := state("ct.example.com"); got != attribution.StateConfirmed {
		t.Fatalf("covered CT name = %s, want confirmed", got)
	}
	if got := state("gone.example.com"); got != attribution.StateRejected {
		t.Fatalf("automation overrode a rejection: %s", got)
	}
}
