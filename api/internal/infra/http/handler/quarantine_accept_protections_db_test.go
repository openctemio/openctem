package handler

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/openctemio/ctis"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/pkg/domain/sensorresult"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Accepting a quarantined report applies it with a person's authority but
// keeps the protocol v2 protections for every item, whatever protocol it
// was stored under (sensor → platform review, F8): a finding with no asset
// of its own does not get an asset invented from the report's metadata.
func TestQuarantineAccept_KeepsV2Protections(t *testing.T) {
	r := newBindingRig(t, "")
	ctx := context.Background()
	report := ctis.Report{Version: "1.0", Tool: &ctis.Tool{Name: "nuclei"},
		Metadata: ctis.ReportMetadata{Scope: &ctis.Scope{Name: "invented.corp.example"}},
		Findings: []ctis.Finding{{Type: ctis.FindingTypeVulnerability, Title: "t", Severity: ctis.SeverityHigh, RuleID: "orphan-rule"}}}
	payload, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	item := &sensorresult.Item{TenantID: r.tenant, SensorID: r.ids["worker"], SensorType: "worker",
		Protocol: sensorresult.ProtocolV1, Route: "ctis", ReportID: shared.NewID().String(), ToolName: "nuclei",
		Reason: sensorresult.ReasonNoCommand, Payload: payload, FindingsCount: 1}
	if err := r.results.Create(ctx, item, sensorresult.DefaultLimits()); err != nil {
		t.Fatal(err)
	}

	out, err := r.svc.AcceptQuarantined(ctx, auditapp.AuditContext{}, r.tenant, item.ID, r.seedUser())
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	if out.FindingsCreated != 0 {
		t.Fatalf("an accepted finding without an asset was applied (%d created)", out.FindingsCreated)
	}
	if n := r.count(`SELECT COUNT(*) FROM assets WHERE tenant_id = $1 AND name = 'invented.corp.example'`, r.tenant.String()); n != 0 {
		t.Fatal("an asset was invented from the quarantined report's metadata")
	}
}
