package handler

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/openctemio/ctis/v2"

	auditapp "github.com/openctemio/openctem/server/internal/app/audit"
	"github.com/openctemio/openctem/server/internal/infra/postgres"
	"github.com/openctemio/openctem/server/pkg/domain/sensorresult"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// Accepting a quarantined report applies it with a person's authority but
// keeps the protocol v2 protections for every item, whatever protocol it
// was stored under (sensor → platform review, F8): a finding with no asset
// of its own does not get an asset invented from the report's metadata.
func TestQuarantineAccept_KeepsV2Protections(t *testing.T) {
	r := newBindingRig(t, "")
	ctx := context.Background()
	report := ctis.Report{Version: ctis.SchemaVersion, Tool: &ctis.Tool{Name: "nuclei"},
		Metadata: ctis.ReportMetadata{ID: ctis.NewReportID(), GeneratedAt: time.Now().UTC(), Channel: ctis.ChannelScanner},
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

	// CTIS 2.0: a finding names an asset of its document; one without is
	// an invalid report, refused before anything is stored, and no asset is
	// invented for it.
	assetsBefore := r.count(`SELECT COUNT(*) FROM assets WHERE tenant_id = $1`, r.tenant.String())
	out, err := r.svc.AcceptQuarantined(ctx, auditapp.AuditContext{}, r.tenant, item.ID, r.seedUser())
	if err == nil {
		t.Fatalf("a report with an asset-less finding was accepted (%+v)", out)
	}
	if n := r.count(`SELECT COUNT(*) FROM findings WHERE tenant_id = $1`, r.tenant.String()); n != 0 {
		t.Fatalf("an accepted finding without an asset was applied (%d findings)", n)
	}
	if n := r.count(`SELECT COUNT(*) FROM assets WHERE tenant_id = $1`, r.tenant.String()); n != assetsBefore {
		t.Fatalf("%d assets were invented for the quarantined report", n-assetsBefore)
	}
}

// oversizedResults serves the stored item with a report over the ingest
// limits, so the accept's apply fails.
type oversizedResults struct {
	*postgres.SensorResultRepository
}

func (o oversizedResults) Get(ctx context.Context, tenantID, id shared.ID) (*sensorresult.Item, error) {
	item, err := o.SensorResultRepository.Get(ctx, tenantID, id)
	if err != nil {
		return nil, err
	}
	rep := ctis.Report{Version: ctis.SchemaVersion, Tool: &ctis.Tool{Name: "nuclei"},
		Metadata: ctis.ReportMetadata{ID: ctis.NewReportID(), GeneratedAt: time.Now().UTC(), Channel: ctis.ChannelScanner},
		Assets:   make([]ctis.Asset, 100_001)}
	for i := range rep.Assets {
		rep.Assets[i] = ctis.Asset{ID: "a" + strconv.Itoa(i), Type: ctis.AssetTypeDomainName, Value: "x.example.com"}
	}
	item.Payload, _ = json.Marshal(rep)
	return item, nil
}

// An accept whose apply fails leaves the item pending (it was marked
// accepted before the apply, so a failed apply left an accepted item that
// was never applied); a claim held by a running accept refuses a second
// accept and a discard; a successful accept marks it accepted.
func TestQuarantineAccept_AcceptedOnlyAfterApply(t *testing.T) {
	r := newBindingRig(t, "")
	ctx := context.Background()
	report := ctis.Report{Version: ctis.SchemaVersion, Tool: &ctis.Tool{Name: "nuclei"},
		Metadata: ctis.ReportMetadata{ID: ctis.NewReportID(), GeneratedAt: time.Now().UTC(), Channel: ctis.ChannelScanner},
		Assets:   []ctis.Asset{{ID: "a", Type: ctis.AssetTypeDomainName, Value: "apply.example.com"}},
		Findings: []ctis.Finding{{Type: ctis.FindingTypeVulnerability, Title: "t", Severity: ctis.SeverityHigh, RuleID: "r", AssetRef: "a"}}}
	payload, _ := json.Marshal(report)
	item := &sensorresult.Item{TenantID: r.tenant, SensorID: r.ids["worker"], SensorType: "worker",
		Protocol: sensorresult.ProtocolV1, Route: "ctis", ReportID: shared.NewID().String(), ToolName: "nuclei",
		Reason: sensorresult.ReasonNoCommand, Payload: payload, FindingsCount: 1}
	if err := r.results.Create(ctx, item, sensorresult.DefaultLimits()); err != nil {
		t.Fatal(err)
	}
	status := func() (string, bool) {
		var s string
		var applying bool
		if err := r.db.QueryRow(`SELECT status, applying_at IS NOT NULL FROM sensor_result_quarantine WHERE id = $1`, item.ID.String()).Scan(&s, &applying); err != nil {
			t.Fatal(err)
		}
		return s, applying
	}
	user := r.seedUser()

	// The apply fails: the item stays pending, unclaimed.
	r.svc.SetResultQuarantine(oversizedResults{r.results}, sensorresult.DefaultLimits())
	if _, err := r.svc.AcceptQuarantined(ctx, auditapp.AuditContext{}, r.tenant, item.ID, user); err == nil {
		t.Fatal("the apply of a report over the limits succeeded")
	}
	if s, applying := status(); s != "pending" || applying {
		t.Fatalf("after a failed apply: status %s, claimed %v; want pending, unclaimed", s, applying)
	}
	r.svc.SetResultQuarantine(r.results, sensorresult.DefaultLimits())

	// A fresh claim refuses a second accept and a discard.
	if err := r.results.ClaimForApply(ctx, r.tenant, item.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := r.svc.AcceptQuarantined(ctx, auditapp.AuditContext{}, r.tenant, item.ID, user); !errors.Is(err, sensorresult.ErrBeingApplied) {
		t.Fatalf("second accept while claimed: %v", err)
	}
	if err := r.results.Review(ctx, r.tenant, item.ID, sensorresult.StatusDiscarded, &user); !errors.Is(err, sensorresult.ErrBeingApplied) {
		t.Fatalf("discard while claimed: %v", err)
	}
	// Another tenant cannot claim or release it.
	if err := r.results.ClaimForApply(ctx, shared.NewID(), item.ID); !errors.Is(err, sensorresult.ErrNotFound) {
		t.Fatalf("other tenant claim: %v", err)
	}
	if err := r.results.ReleaseApply(ctx, r.tenant, item.ID); err != nil {
		t.Fatal(err)
	}

	// A successful accept marks it accepted.
	if _, err := r.svc.AcceptQuarantined(ctx, auditapp.AuditContext{}, r.tenant, item.ID, user); err != nil {
		t.Fatalf("accept: %v", err)
	}
	if s, applying := status(); s != "accepted" || applying {
		t.Fatalf("after the apply: status %s, claimed %v", s, applying)
	}
}
