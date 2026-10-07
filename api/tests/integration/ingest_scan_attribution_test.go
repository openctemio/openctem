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

type reportedName struct {
	name, root string // root: the report's root_domain property ("" for none)
}

// Attribution of what a sensor report writes, through the real ingest
// (RFC-036 §6.4, research/22 E7, 22b S2/S3):
//   - an unsolicited report's new names are candidates, with no evidence;
//   - a bound report's command target gets tenant_scanned; a name the scan
//     found gets tenant_scan_discovered and a needs_review record, or
//     confirmed under a verified domain;
//   - a scan never takes a name past review and never overrides a person;
//   - root_domain must be a registrable parent of the reported name;
//   - nothing crosses tenants.
func TestIngest_SensorReportAttribution(t *testing.T) {
	r := newV2Rig(t, ingest.DefaultBlindingGuard())
	tn := r.newTenant("subfinder")
	other := r.newTenant("subfinder")
	db := &postgres.DB{DB: r.db}
	ctx := context.Background()
	attr := postgres.NewAttributionRepository(db)
	svc := ingest.NewService(
		postgres.NewAssetRepository(db), postgres.NewFindingRepository(db),
		postgres.NewVulnerabilityRepository(db), postgres.NewComponentRepository(db),
		postgres.NewSensorRepository(db), postgres.NewBranchRepository(db), postgres.NewTenantRepository(db),
		postgres.NewAuditRepository(db), logger.NewNop())
	svc.SetScanAttributionStamper(easm.NewScanStamper(attr, postgres.NewVerifiedDomainNameRepository(db)))
	tid := tn.tenant
	agt := &sensor.Sensor{ID: tn.sensor, TenantID: &tid, Type: sensor.SensorTypeWorker, Status: sensor.SensorStatusActive}
	oid := other.tenant
	otherAgt := &sensor.Sensor{ID: other.sensor, TenantID: &oid, Type: sensor.SensorTypeWorker, Status: sensor.SensorStatusActive}

	if _, err := r.db.ExecContext(ctx, `INSERT INTO verified_domains (id, tenant_id, domain, verification_token, status, verified_at)
		VALUES ($1, $2, 'proven.example.org', 'tok', 'verified', now())`, shared.NewID().String(), tid.String()); err != nil {
		t.Fatal(err)
	}

	run := func(a *sensor.Sensor, bind ingest.Binding, names ...reportedName) {
		t.Helper()
		assets := make([]ctis.Asset, 0, len(names))
		for i, n := range names {
			ca := ctis.Asset{ID: string(rune('a' + i)), Type: ctis.AssetTypeSubdomain, Value: n.name}
			if n.root != "" {
				ca.Properties = map[string]any{"root_domain": n.root}
			}
			assets = append(assets, ca)
		}
		rep := &ctis.Report{Version: "1.0", Tool: &ctis.Tool{Name: "subfinder"}, Assets: assets,
			Metadata: ctis.ReportMetadata{ID: "rep-1", Timestamp: time.Now().UTC()}}
		out, err := svc.Ingest(ctx, a, ingest.Input{Report: rep, Options: ingest.Options{Binding: bind}})
		if err != nil || len(out.Errors) > 0 {
			t.Fatalf("Ingest: %v %v", err, out.Errors)
		}
	}
	idIn := func(tenant shared.ID, name string) string {
		t.Helper()
		var id string
		if err := r.db.QueryRowContext(ctx, `SELECT id FROM assets WHERE tenant_id = $1 AND name = $2`, tenant.String(), name).Scan(&id); err != nil {
			return ""
		}
		return id
	}
	idOf := func(name string) string {
		t.Helper()
		id := idIn(tid, name)
		if id == "" {
			t.Fatalf("asset %s not found", name)
		}
		return id
	}
	evidence := func(name string, rule attribution.Rule) (n int, cmd string) {
		t.Helper()
		_ = r.db.QueryRowContext(ctx, `SELECT count(*), coalesce(max(observed->>'command_id'), '') FROM easm_evidence
			WHERE tenant_id = $1 AND asset_id = $2 AND rule = $3`, tid.String(), idOf(name), string(rule)).Scan(&n, &cmd)
		return n, cmd
	}
	state := func(tenant shared.ID, id string) attribution.State {
		t.Helper()
		recs, err := attr.Records(ctx, tenant, []string{id})
		if err != nil {
			t.Fatal(err)
		}
		return recs[id].State
	}
	sn := func(name string) reportedName { return reportedName{name: name} }

	// An unsolicited report: new names are candidates, no evidence.
	run(agt, ingest.Binding{}, sn("ct.example.com"), sn("gone.example.com"))
	if got := state(tid, idOf("ct.example.com")); got != attribution.StateCandidate {
		t.Fatalf("unsolicited new name = %q, want candidate", got)
	}
	if n, _ := evidence("ct.example.com", attribution.RuleTenantScanned); n != 0 {
		t.Fatal("an unsolicited report stamped tenant_scanned")
	}
	// CT then puts one in review; a person rejects the other.
	if err := attr.SaveAutomatic(ctx, tid, idOf("ct.example.com"), attribution.Decision{State: attribution.StateNeedsReview, Confidence: 85, Reason: attribution.RuleAssertedRoot}); err != nil {
		t.Fatal(err)
	}
	if err := attr.UpsertEvidence(ctx, tid, []attribution.Evidence{{AssetID: idOf("ct.example.com"), Rule: attribution.RuleAssertedRoot, Technique: "cert_transparency", Source: "crt.sh", Weight: 0.85}}); err != nil {
		t.Fatal(err)
	}
	if _, err := attr.SaveDecision(ctx, tid, idOf("gone.example.com"), attribution.StateRejected, ""); err != nil {
		t.Fatal(err)
	}

	// A command for new.example.com reports its target, a child it found,
	// and ct.example.com outside its targets.
	cmd := shared.NewID()
	run(agt, ingest.Binding{Kind: ingest.BindingCommand, CommandID: &cmd, Targets: []string{"new.example.com"}},
		sn("new.example.com"), sn("api.new.example.com"), sn("ct.example.com"))
	if n, c := evidence("new.example.com", attribution.RuleTenantScanned); n != 1 || c != cmd.String() {
		t.Fatalf("command target: %d tenant_scanned rows, command %q", n, c)
	}
	if got := state(tid, idOf("new.example.com")); got != "" {
		t.Fatalf("a new command target got record %q; the active-scan gate decides by scope", got)
	}
	if n, _ := evidence("api.new.example.com", attribution.RuleScanDiscovered); n != 1 {
		t.Fatal("a discovered name has no tenant_scan_discovered evidence")
	}
	if n, _ := evidence("api.new.example.com", attribution.RuleTenantScanned); n != 0 {
		t.Fatal("a discovered name was stamped as a scanned target")
	}
	if got := state(tid, idOf("api.new.example.com")); got != attribution.StateNeedsReview {
		t.Fatalf("discovered name = %q, want needs_review", got)
	}
	if n, _ := evidence("ct.example.com", attribution.RuleTenantScanned); n != 0 || state(tid, idOf("ct.example.com")) != attribution.StateNeedsReview {
		t.Fatal("a command raised an asset outside its targets")
	}

	// A command that targets the names in review and rejected: a scan does
	// not take them past review (E7, 22b S3), nor override a person.
	cmd2 := shared.NewID()
	run(agt, ingest.Binding{Kind: ingest.BindingCommand, CommandID: &cmd2, Targets: []string{"ct.example.com", "gone.example.com"}},
		sn("ct.example.com"), sn("gone.example.com"))
	if got := state(tid, idOf("ct.example.com")); got != attribution.StateNeedsReview {
		t.Fatalf("a scan confirmed a name in review: %s", got)
	}
	if got := state(tid, idOf("gone.example.com")); got != attribution.StateRejected {
		t.Fatalf("automation overrode a rejection: %s", got)
	}

	// A name a scan found under a verified domain is confirmed.
	cmd3 := shared.NewID()
	run(agt, ingest.Binding{Kind: ingest.BindingCommand, CommandID: &cmd3, Targets: []string{"proven.example.org"}},
		sn("x.proven.example.org"))
	if got := state(tid, idOf("x.proven.example.org")); got != attribution.StateConfirmed {
		t.Fatalf("discovered under a verified domain = %q, want confirmed", got)
	}

	// root_domain: an unrelated or public-suffix root creates nothing; a
	// registrable parent creates the domain, in review.
	cmd4 := shared.NewID()
	run(agt, ingest.Binding{Kind: ingest.BindingCommand, CommandID: &cmd4, Targets: []string{"www.acme.example.net"}},
		reportedName{"www.acme.example.net", "victim.example.com"}, reportedName{"api.acme.example.net", "net"},
		reportedName{"mail.acme.example.net", "example.net"})
	for _, n := range []string{"victim.example.com", "net"} {
		if idIn(tid, n) != "" {
			t.Fatalf("root_domain %q was created from a name it is not a parent of", n)
		}
	}
	if got := state(tid, idOf("example.net")); got != attribution.StateNeedsReview {
		t.Fatalf("auto-created root domain = %q, want needs_review", got)
	}

	// Cross-tenant: the other tenant's sensor reporting the same names
	// writes nothing on this tenant's assets, and this tenant's records
	// do not follow the names into the other tenant.
	cmd5 := shared.NewID()
	run(otherAgt, ingest.Binding{Kind: ingest.BindingCommand, CommandID: &cmd5, Targets: []string{"ct.example.com"}},
		sn("ct.example.com"))
	if got := state(tid, idOf("ct.example.com")); got != attribution.StateNeedsReview {
		t.Fatalf("another tenant's report changed this tenant's record: %s", got)
	}
	if got := state(oid, idIn(oid, "ct.example.com")); got != "" {
		t.Fatalf("the other tenant's own target got this tenant's state %q", got)
	}
}
