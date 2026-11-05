package integration

// Results outside a command's targets are recorded, never dropped (research
// 436; docs/architecture/sensor-result-binding.md, "Hostname-scoped jobs"):
// the asset a scan reached after a redirect is created in the sending
// sensor's tenant with its finding, it grants nothing, it never changes
// another tenant's asset of the same name, and the run's coverage does not
// treat it as covered.

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/openctemio/ctis/v2"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// boundScanCommand seeds a running scan command of the tenant's sensor for
// tool on the given targets.
func (r *v2Rig) boundScanCommand(tn v2Tenant, tool string, targets ...string) shared.ID {
	r.t.Helper()
	cmdID := shared.NewID()
	body, _ := json.Marshal(map[string]any{"scanner": tool, "targets": targets})
	if _, err := r.db.Exec(`INSERT INTO commands (id, tenant_id, sensor_id, type, priority, payload, status, created_at, expires_at)
		VALUES ($1, $2, $3, 'scan', 'normal', $4, 'running', NOW(), NOW() + interval '1 hour')`,
		cmdID.String(), tn.tenant.String(), tn.sensor.String(), string(body)); err != nil {
		r.t.Fatalf("seed command: %v", err)
	}
	return cmdID
}

func webSegment(tool string, assets map[string]string, findings map[string]string) *ctis.Report {
	r := &ctis.Report{
		Version:  ctis.SchemaVersion,
		Metadata: ctis.ReportMetadata{ID: ctis.NewReportID(), GeneratedAt: time.Now().UTC().Add(-time.Minute)},
		Tool:     &ctis.Tool{Name: tool},
	}
	for id, origin := range assets {
		r.Assets = append(r.Assets, ctis.Asset{ID: id, Type: ctis.AssetTypeWebOrigin, Value: origin})
	}
	for rule, ref := range findings {
		r.Findings = append(r.Findings, ctis.Finding{Type: ctis.FindingTypeVulnerability, Title: "finding " + rule,
			Severity: ctis.SeverityHigh, RuleID: rule, AssetRef: ref})
	}
	return r
}

func TestIngestOutsideTargets_RecordedInTheSendersTenantOnly(t *testing.T) {
	r, _ := newBindingV2Rig(t)
	ctx := context.Background()
	mine, other := r.newTenant("nuclei"), r.newTenant("nuclei")
	const redirect = "https://login.example.net"

	// The other tenant already tracks the host the redirect reached.
	if _, err := r.db.ExecContext(ctx, `INSERT INTO assets (id, tenant_id, name, asset_type, sub_type, criticality, status, scope, exposure)
		VALUES ($1, $2, $3, 'service', 'http', 'medium', 'active', 'external', 'public')`,
		shared.NewID().String(), other.tenant.String(), redirect); err != nil {
		t.Fatalf("seed other tenant's asset: %v", err)
	}
	var otherBefore time.Time
	if err := r.db.QueryRow(`SELECT updated_at FROM assets WHERE tenant_id = $1 AND name = $2`, other.tenant.String(), redirect).Scan(&otherBefore); err != nil {
		t.Fatal(err)
	}

	cmd := r.boundScanCommand(mine, "nuclei", "https://app.example.com")
	seg := webSegment("nuclei",
		map[string]string{"target": "https://app.example.com", "redir": redirect},
		map[string]string{"on-target": "target", "after-redirect": "redir"})
	st := r.sendWhole(mine, r.openAs(mine, reportID(40), "worker", &cmd, seg), seg)

	// Nothing is lost: both findings are stored, nothing is rejected.
	if st.Accepted.Findings != 2 || st.Rejected.Findings != 0 || st.Rejected.Assets != 0 {
		t.Fatalf("status %+v, want both findings and assets accepted", st)
	}
	var assetID string
	if err := r.db.QueryRow(`SELECT id::text FROM assets WHERE tenant_id = $1 AND name = $2`, mine.tenant.String(), redirect).Scan(&assetID); err != nil {
		t.Fatalf("the host outside the targets was not recorded: %v", err)
	}
	var onIt int
	if err := r.db.QueryRow(`SELECT COUNT(*) FROM findings WHERE tenant_id = $1 AND asset_id = $2 AND rule_id = 'after-redirect'`,
		mine.tenant.String(), assetID).Scan(&onIt); err != nil || onIt != 1 {
		t.Fatalf("finding on the recorded host: %d (%v)", onIt, err)
	}
	// Recording grants nothing: no confirmed attribution for it.
	var confirmed int
	if err := r.db.QueryRow(`SELECT COUNT(*) FROM asset_attributions WHERE tenant_id = $1 AND asset_id = $2 AND state = 'confirmed'`,
		mine.tenant.String(), assetID).Scan(&confirmed); err != nil || confirmed != 0 {
		t.Fatalf("a host outside the targets was confirmed: %d (%v)", confirmed, err)
	}

	// Tenant isolation: the other tenant's asset and findings are untouched.
	var otherAfter time.Time
	if err := r.db.QueryRow(`SELECT updated_at FROM assets WHERE tenant_id = $1 AND name = $2`, other.tenant.String(), redirect).Scan(&otherAfter); err != nil {
		t.Fatal(err)
	}
	if !otherAfter.Equal(otherBefore) || r.countFindings(other, "") != 0 {
		t.Fatal("a report of one tenant changed another tenant's asset of the same name")
	}
	if n := r.countAssets(other); n != 1 {
		t.Fatalf("other tenant has %d assets, want its own 1", n)
	}
}
