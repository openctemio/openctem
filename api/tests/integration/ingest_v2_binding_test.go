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
	return newBindingV2RigGuard(t, ingest.DefaultBlindingGuard())
}

func newBindingV2RigGuard(t *testing.T, guard ingest.BlindingGuard) (*v2Rig, *postgres.SensorResultRepository) {
	t.Helper()
	var results *postgres.SensorResultRepository
	r := newV2RigWith(t, guard, func(svc *ingest.Service, db *postgres.DB) {
		results = postgres.NewSensorResultRepository(db)
		svc.SetResultQuarantine(results, sensorresult.DefaultLimits())
		svc.SetCommandReader(postgres.NewCommandRepository(db))
		// One blinding guard for the commit and the command-completion
		// evaluation, as in production.
		svc.SetCoverageAutoResolve(ingest.CoverageAutoResolveDryRun, guard)
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

// runCommand is a scan command for the tenant's sensor that targets its
// repository, optionally queued by a scan with the given profile ("" = no
// scan), with the given status and exit code: one run of the scanner.
func (r *v2Rig) runCommand(tn v2Tenant, tool, profileID, status string, exitCode int) shared.ID {
	r.t.Helper()
	cmdID := shared.NewID()
	payload := map[string]any{"scanner": tool, "targets": []string{"https://" + tn.repo + ".git"}}
	if profileID != "" {
		scanID := shared.NewID()
		if _, err := r.db.Exec(`INSERT INTO scans (id, tenant_id, name, scan_type, scanner_name, targets, profile_id)
			VALUES ($1, $2, $3, 'single', $4, ARRAY[$5], $6)`, scanID.String(), tn.tenant.String(), "scan-"+scanID.String(),
			tool, tn.repo, profileID); err != nil {
			r.t.Fatalf("seed scan: %v", err)
		}
		payload["scan_id"] = scanID.String()
	}
	body, _ := json.Marshal(payload)
	result, _ := json.Marshal(map[string]any{"exit_code": exitCode})
	if _, err := r.db.Exec(`INSERT INTO commands (id, tenant_id, sensor_id, type, priority, payload, status, result, created_at, expires_at)
		VALUES ($1, $2, $3, 'scan', 'normal', $4, $5, $6, NOW(), NOW() + interval '1 hour')`,
		cmdID.String(), tn.tenant.String(), tn.sensor.String(), string(body), status, string(result)); err != nil {
		r.t.Fatalf("seed command: %v", err)
	}
	return cmdID
}

// scanProfile seeds a scan profile for the tenant.
func (r *v2Rig) scanProfile(tn v2Tenant, name string) string {
	r.t.Helper()
	id := shared.NewID()
	if _, err := r.db.Exec(`INSERT INTO scan_profiles (id, tenant_id, name) VALUES ($1, $2, $3)`,
		id.String(), tn.tenant.String(), name+"-"+id.String()); err != nil {
		r.t.Fatalf("seed scan profile: %v", err)
	}
	return id.String()
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
// commit never auto-resolves there, nor on a warn-mode tenant.
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

	// Warn mode still applies the upload, but a report without a command
	// never closes a finding (owner decision O11, research 18 F3).
	p := sensorresult.Policy{TenantID: tn.tenant, Mode: sensorresult.ModeWarn}
	if err := results.SavePolicy(context.Background(), &p); err != nil {
		t.Fatal(err)
	}
	st = r.sendWhole(tn, r.openAs(tn, reportID(4), "runner", nil, next), next)
	if st.AutoResolve != protov2.AutoResolveSkipped || r.countFindings(tn, "resolved") != 0 {
		t.Fatalf("a warn-mode upload without a command closed findings: %+v", st)
	}
}

// A report bound to a command auto-resolves only on the assets the command
// covers: a stale finding on another asset the report merely names stays
// open.
func TestIngestV2Binding_BoundCommitResolvesOnlyCoveredAssets(t *testing.T) {
	r, _ := newBindingV2Rig(t)
	tn := r.newTenant("semgrep")
	other := "github.com/acme/other-" + tn.tenant.String()[:8]
	first := r.runCommand(tn, "semgrep", "", "completed", 0)
	second := r.runCommand(tn, "semgrep", "", "completed", 0)

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
	if st := r.sendWhole(tn, r.openAs(tn, reportID(5), "worker", &first, base), base); st.Accepted.Findings != 3 {
		t.Fatalf("bound baseline: %+v", st)
	}
	next := withOther(tn.segment("semgrep", true, v2Finding{rule: "a", assetRef: "repo"}))
	st := r.sendWhole(tn, r.openAs(tn, reportID(6), "worker", &second, next), next)
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
