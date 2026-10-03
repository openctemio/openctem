package integration

// RFC-040 §5.3 (owner decision Q6 (a)) on protocol v2: a report without a
// command from a worker is quarantined on a quarantine-mode tenant; a CI
// runner's is applied but never auto-resolves there; a report bound to a
// command auto-resolves only on the assets its command covers.

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/ingestreport"
	"github.com/openctemio/openctem/api/pkg/domain/sensorresult"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	protov2 "github.com/openctemio/openctem/api/pkg/sensorproto/v2"
)

func newBindingV2Rig(t *testing.T) (*v2Rig, *postgres.SensorResultRepository) {
	t.Helper()
	var results *postgres.SensorResultRepository
	r := newV2RigWith(t, ingest.DefaultBlindingGuard(), func(svc *ingest.Service, db *postgres.DB) {
		results = postgres.NewSensorResultRepository(db)
		svc.SetResultQuarantine(results, sensorresult.DefaultLimits())
		svc.SetCommandReader(postgres.NewCommandRepository(db))
	})
	return r, results
}

// openAs creates a report the way the accept side does, for a sensor role
// and an optional command.
func (r *v2Rig) openAs(tn v2Tenant, reportID, sensorType string, commandID *shared.ID, header *ctis.Report) *ingestreport.Report {
	r.t.Helper()
	canonical, digest, err := ingest.V2HeaderOf(header)
	if err != nil {
		r.t.Fatal(err)
	}
	now := time.Now()
	rep := &ingestreport.Report{ID: shared.NewID(), TenantID: tn.tenant, SensorID: tn.sensor, ReportID: reportID,
		CommandID: commandID, State: protov2.StateReceiving, MediaType: protov2.MediaTypeCTIS, SensorType: sensorType,
		HeaderDigest: digest, Header: canonical, ToolName: header.Tool.Name, ExpiresAt: now.Add(time.Hour), ReceivedAt: now}
	if err := r.reports.Create(context.Background(), rep); err != nil {
		r.t.Fatalf("create report: %v", err)
	}
	return rep
}

func (r *v2Rig) sendWhole(tn v2Tenant, rep *ingestreport.Report, seg *ctis.Report) protov2.Status {
	r.t.Helper()
	r.put(tn, rep, 0, seg)
	r.process(rep, 0)
	if !r.commit(tn, rep, 1) {
		r.t.Fatal("commit refused")
	}
	return r.status(rep)
}

func (r *v2Rig) setSensorType(tn v2Tenant, typ string) {
	r.t.Helper()
	if _, err := r.db.Exec(`UPDATE sensors SET type = $2 WHERE id = $1`, tn.sensor.String(), typ); err != nil {
		r.t.Fatal(err)
	}
}

func reportID(n int) string {
	return "0192a3b4-0000-7000-8000-0000000040" + string(rune('0'+n/10)) + string(rune('0'+n%10))
}

// A worker's report without a command, on a new tenant: every item is
// quarantined, nothing is applied, the status says so, and the segment waits
// in the quarantine for review.
func TestIngestV2Binding_UnsolicitedWorkerQuarantined(t *testing.T) {
	r, results := newBindingV2Rig(t)
	tn := r.newTenant("semgrep")
	seg := tn.segment("semgrep", true, v2Finding{rule: "a", assetRef: "repo"}, v2Finding{rule: "b", assetRef: "repo"})
	st := r.sendWhole(tn, r.openAs(tn, reportID(1), "worker", nil, seg), seg)

	if st.State != protov2.StateCompleted || st.Quarantined.Findings != 2 || st.Quarantined.Assets != 1 || st.Accepted.Findings != 0 {
		t.Fatalf("status %+v, want every item quarantined", st)
	}
	if len(st.Errors) != 1 || st.Errors[0].Code != protov2.CodeQuarantinedNoCommand {
		t.Fatalf("status errors %+v, want quarantined_no_command", st.Errors)
	}
	if n := r.countFindings(tn, ""); n != 0 {
		t.Fatalf("a quarantined report wrote %d findings", n)
	}
	if n := r.countAssets(tn); n != 0 {
		t.Fatalf("a quarantined report wrote %d assets", n)
	}
	items, total, err := results.List(context.Background(), tn.tenant, sensorresult.ListFilter{})
	if err != nil || total != 1 || items[0].Protocol != sensorresult.ProtocolV2 || items[0].Segment == nil || *items[0].Segment != 0 ||
		items[0].ReportID != reportID(1) || items[0].FindingsCount != 2 {
		t.Fatalf("quarantine %v %d %+v", err, total, items)
	}
}

// A CI runner's report without a command is applied on a new tenant, but its
// commit never auto-resolves there; once the tenant is on warn (every tenant
// that existed before RFC-040) it auto-resolves as before.
func TestIngestV2Binding_RunnerAppliedNoAutoResolveInQuarantineMode(t *testing.T) {
	r, results := newBindingV2Rig(t)
	tn := r.newTenant("semgrep")
	r.setSensorType(tn, "runner")

	base := tn.segment("semgrep", true, v2Finding{rule: "a", assetRef: "repo"}, v2Finding{rule: "b", assetRef: "repo"})
	if st := r.sendWhole(tn, r.openAs(tn, reportID(2), "runner", nil, base), base); st.Accepted.Findings != 2 || st.Quarantined.Findings != 0 {
		t.Fatalf("runner upload not applied: %+v", st)
	}
	next := tn.segment("semgrep", true, v2Finding{rule: "a", assetRef: "repo"})
	st := r.sendWhole(tn, r.openAs(tn, reportID(3), "runner", nil, next), next)
	if st.AutoResolve != protov2.AutoResolveSkipped || r.countFindings(tn, "resolved") != 0 {
		t.Fatalf("an unsolicited report auto-resolved on a quarantine-mode tenant: %+v", st)
	}

	p := sensorresult.Policy{TenantID: tn.tenant, Mode: sensorresult.ModeWarn}
	if err := results.SavePolicy(context.Background(), &p); err != nil {
		t.Fatal(err)
	}
	st = r.sendWhole(tn, r.openAs(tn, reportID(4), "runner", nil, next), next)
	if st.AutoResolve != protov2.AutoResolveApplied || r.countFindings(tn, "resolved") != 1 {
		t.Fatalf("warn-mode CI upload no longer auto-resolves: %+v", st)
	}
}

// A report bound to a command auto-resolves only on the assets the command
// covers: a stale finding on another asset the report merely names stays
// open.
func TestIngestV2Binding_BoundCommitResolvesOnlyCoveredAssets(t *testing.T) {
	r, _ := newBindingV2Rig(t)
	tn := r.newTenant("semgrep")
	other := "github.com/acme/other-" + tn.tenant.String()[:8]
	cmdID := shared.NewID()
	payload, _ := json.Marshal(map[string]any{"scanner": "semgrep", "targets": []string{"https://" + tn.repo + ".git"}})
	if _, err := r.db.Exec(`INSERT INTO commands (id, tenant_id, sensor_id, type, priority, payload, status, created_at, expires_at)
		VALUES ($1, $2, $3, 'scan', 'normal', $4, 'running', NOW(), NOW() + interval '1 hour')`,
		cmdID.String(), tn.tenant.String(), tn.sensor.String(), string(payload)); err != nil {
		t.Fatal(err)
	}

	withOther := func(seg *ctis.Report, otherRules ...string) *ctis.Report {
		seg.Assets = append(seg.Assets, ctis.Asset{ID: "other", Type: ctis.AssetTypeRepository, Value: other})
		for _, rule := range otherRules {
			seg.Findings = append(seg.Findings, ctis.Finding{Type: ctis.FindingTypeVulnerability, Title: "finding " + rule,
				Severity: ctis.SeverityHigh, RuleID: rule, AssetRef: "other",
				Location: &ctis.FindingLocation{Path: "src/" + rule + ".go", StartLine: 10}})
		}
		return seg
	}
	base := withOther(tn.segment("semgrep", true, v2Finding{rule: "a", assetRef: "repo"}, v2Finding{rule: "gone", assetRef: "repo"}), "o1")
	if st := r.sendWhole(tn, r.openAs(tn, reportID(5), "worker", &cmdID, base), base); st.Accepted.Findings != 3 {
		t.Fatalf("bound baseline: %+v", st)
	}
	next := withOther(tn.segment("semgrep", true, v2Finding{rule: "a", assetRef: "repo"}))
	st := r.sendWhole(tn, r.openAs(tn, reportID(6), "worker", &cmdID, next), next)
	if st.AutoResolve != protov2.AutoResolveApplied || st.AutoResolved != 1 {
		t.Fatalf("bound commit: %+v, want exactly the covered stale finding resolved", st)
	}
	var otherStatus string
	if err := r.db.QueryRow(`SELECT status FROM findings WHERE tenant_id = $1 AND rule_id = 'o1'`, tn.tenant.String()).Scan(&otherStatus); err != nil {
		t.Fatal(err)
	}
	if otherStatus == "resolved" {
		t.Fatal("a bound report auto-resolved a finding on an asset outside its command's targets")
	}
}
