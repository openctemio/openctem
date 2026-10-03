package integration

// RFC-043 P0: a network finding without a CVE fell to the generic fingerprint
// (rule + title), which ignores the port, so one scanner plugin on ports 443
// and 8443 of a host was one finding. The port is now part of the key; a
// finding stored under the old key is re-keyed to the first port that reports
// it, so its triage carries over.

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func netPortIngest(t *testing.T) (r *v2Rig, tn v2Tenant, scan func(ports ...int)) {
	t.Helper()
	r = newV2Rig(t, ingest.DefaultBlindingGuard())
	tn = r.newTenant("nessus")
	db := &postgres.DB{DB: r.db}
	svc := ingest.NewService(
		postgres.NewAssetRepository(db), postgres.NewFindingRepository(db),
		postgres.NewVulnerabilityRepository(db), postgres.NewComponentRepository(db),
		postgres.NewSensorRepository(db), postgres.NewBranchRepository(db), postgres.NewTenantRepository(db),
		postgres.NewAuditRepository(db), logger.NewNop())
	tid := tn.tenant
	agt := &sensor.Sensor{ID: tn.sensor, TenantID: &tid, Type: sensor.SensorTypeWorker, Status: sensor.SensorStatusActive}
	scan = func(ports ...int) {
		t.Helper()
		rep := &ctis.Report{Version: "1.0", Tool: &ctis.Tool{Name: "nessus"},
			Metadata: ctis.ReportMetadata{ID: shared.NewID().String(), Timestamp: time.Now().UTC()},
			Assets:   []ctis.Asset{{ID: "h", Type: ctis.AssetTypeHost, Value: "tls-" + tn.tenant.String()[:8] + ".example.com"}}}
		for _, p := range ports {
			f := ctis.Finding{Type: ctis.FindingTypeVulnerability, Title: "SSL Certificate Cannot Be Trusted",
				Severity: ctis.SeverityMedium, RuleID: "51192", AssetRef: "h"}
			if p > 0 {
				f.Network = &ctis.NetworkLocation{Port: p, Protocol: "tcp"}
			}
			rep.Findings = append(rep.Findings, f)
		}
		out, err := svc.Ingest(context.Background(), agt, ingest.Input{Report: rep})
		if err != nil || len(out.Errors) > 0 {
			t.Fatalf("ingest: %v %v", err, out.Errors)
		}
	}
	return r, tn, scan
}

func TestNetworkFindingWithoutCVE_PortIsPartOfTheKey(t *testing.T) {
	r, tn, scan := netPortIngest(t)
	scan(443, 8443)
	var n int
	if err := r.db.QueryRow(`SELECT count(*) FROM findings WHERE tenant_id = $1 AND rule_id = '51192'`, tn.tenant.String()).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("plugin 51192 on ports 443 and 8443: %d findings, want 2", n)
	}
}

// A finding stored under the old, port-less key (what every port-specific
// no-CVE finding got before this change; a host-level report still gets it)
// keeps its false-positive verdict: the first port that reports it takes the
// row over, the other port becomes a new finding.
func TestNetworkFindingWithoutCVE_LegacyRowKeepsItsTriage(t *testing.T) {
	r, tn, scan := netPortIngest(t)
	scan(0) // stored under the legacy generic key
	if _, err := r.db.Exec(`UPDATE findings SET status = 'false_positive', resolution = 'false_positive'
		WHERE tenant_id = $1 AND rule_id = '51192'`, tn.tenant.String()); err != nil {
		t.Fatal(err)
	}
	var legacyID string
	if err := r.db.QueryRow(`SELECT id FROM findings WHERE tenant_id = $1 AND rule_id = '51192'`, tn.tenant.String()).Scan(&legacyID); err != nil {
		t.Fatal(err)
	}

	scan(443, 8443)

	rows, err := r.db.Query(`SELECT id, status FROM findings WHERE tenant_id = $1 AND rule_id = '51192'`, tn.tenant.String())
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	statuses := map[string]string{}
	for rows.Next() {
		var id, st string
		if err := rows.Scan(&id, &st); err != nil {
			t.Fatal(err)
		}
		statuses[id] = st
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(statuses) != 2 {
		t.Fatalf("got %d findings (%v), want 2: the legacy row re-keyed to one port + one new", len(statuses), statuses)
	}
	if statuses[legacyID] != "false_positive" {
		t.Fatalf("legacy finding status = %q, want false_positive (triage lost)", statuses[legacyID])
	}
}
