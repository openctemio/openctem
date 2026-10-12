package integration

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// CTIS Finding.Network carries the port a finding was observed on. Ingest used
// it only inside the network-VA fingerprint and dropped it, so a stored finding
// did not know its port (RFC-042 F6). Checked on a migrated database through
// the real ingest: create, re-sighting (a NULL is filled), another port is another finding, a
// finding without a port, and the fingerprint is the one develop computed.
func TestIngest_FindingStoresNetworkPort(t *testing.T) {
	ctx := context.Background()
	r := newV2Rig(t, ingest.DefaultBlindingGuard())
	tn := r.newTenant("nessus")
	db := &postgres.DB{DB: r.db}
	svc := ingest.NewService(
		postgres.NewAssetRepository(db), postgres.NewFindingRepository(db),
		postgres.NewVulnerabilityRepository(db), postgres.NewComponentRepository(db),
		postgres.NewSensorRepository(db), postgres.NewBranchRepository(db), postgres.NewTenantRepository(db),
		postgres.NewAuditRepository(db), logger.NewNop())
	tid := tn.tenant
	agt := &sensor.Sensor{ID: tn.sensor, TenantID: &tid, Type: sensor.SensorTypeWorker, Status: sensor.SensorStatusActive}

	send := func(findings ...ctis.Finding) {
		t.Helper()
		rep := &ctis.Report{Version: "1.0", Tool: &ctis.Tool{Name: "nessus"},
			Metadata: ctis.ReportMetadata{Timestamp: time.Now().UTC()},
			Assets:   []ctis.Asset{{ID: "h", Type: ctis.AssetTypeHost, Value: "web-1.example.com"}},
			Findings: findings}
		for i := range rep.Findings {
			rep.Findings[i].AssetRef = "h"
		}
		out, err := svc.Ingest(ctx, agt, ingest.Input{Report: rep})
		if err != nil || len(out.Errors) > 0 {
			t.Fatalf("Ingest: %v %v", err, out.Errors)
		}
	}
	type row struct {
		port               sql.NullInt64
		transport, service sql.NullString
		fingerprint        string
	}
	read := func(rule string) row {
		t.Helper()
		var x row
		if err := r.db.QueryRowContext(ctx,
			`SELECT network_port, network_transport, network_service, fingerprint FROM findings
			 WHERE tenant_id = $1 AND rule_id = $2
			 ORDER BY created_at LIMIT 1`, tn.tenant.String(), rule).
			Scan(&x.port, &x.transport, &x.service, &x.fingerprint); err != nil {
			t.Fatalf("read finding %s: %v", rule, err)
		}
		return x
	}

	tls := ctis.Finding{Type: ctis.FindingTypeVulnerability, Severity: ctis.SeverityMedium,
		Title: "SSL Certificate Cannot Be Trusted", RuleID: "nessus-51192",
		Network: &ctis.NetworkLocation{Host: "web-1.example.com", Port: 8443, Protocol: "TCP", Service: "https"}}
	hostLevel := ctis.Finding{Type: ctis.FindingTypeVulnerability, Severity: ctis.SeverityLow,
		Title: "OS end of life", RuleID: "nessus-33850"}
	send(tls, hostLevel)

	got := read("nessus-51192")
	if !got.port.Valid || got.port.Int64 != 8443 || got.transport.String != "tcp" || got.service.String != "https" {
		t.Fatalf("stored network = %v/%v/%v, want 8443/tcp/https", got.port, got.transport, got.service)
	}
	if h := read("nessus-33850"); h.port.Valid || h.transport.Valid || h.service.Valid {
		t.Fatalf("finding without a network location stored %v/%v/%v, want NULLs", h.port, h.transport, h.service)
	}

	// The same finding seen again on the same port is the same row and keeps
	// its stored network location.
	send(tls)
	if again := read("nessus-51192"); again.port.Int64 != 8443 || again.fingerprint != got.fingerprint {
		t.Fatalf("re-sighting: port %v fingerprint %s, want 8443 and %s", again.port, again.fingerprint, got.fingerprint)
	}

	// A row stored before this change (NULL) is filled on its next sighting.
	if _, err := r.db.ExecContext(ctx,
		`UPDATE findings SET network_port = NULL, network_transport = NULL, network_service = NULL
		 WHERE tenant_id = $1 AND fingerprint = $2`, tn.tenant.String(), got.fingerprint); err != nil {
		t.Fatal(err)
	}
	send(tls)
	if filled := read("nessus-51192"); filled.port.Int64 != 8443 || filled.transport.String != "tcp" || filled.service.String != "https" {
		t.Fatalf("NULL port not filled on re-sighting: %v/%v/%v", filled.port, filled.transport, filled.service)
	}

	// The same plugin on another port is another finding (RFC-043 #920: a
	// network finding without a CVE is keyed on port and transport).
	other := tls
	other.Network = &ctis.NetworkLocation{Port: 443, Protocol: "tcp", Service: "https"}
	send(other)
	var ports []int64
	rows, err := r.db.QueryContext(ctx, `SELECT network_port FROM findings
		WHERE tenant_id = $1 AND rule_id = 'nessus-51192' ORDER BY network_port`, tn.tenant.String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var p int64
		if err := rows.Scan(&p); err != nil {
			t.Fatal(err)
		}
		ports = append(ports, p)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(ports) != 2 || ports[0] != 443 || ports[1] != 8443 {
		t.Fatalf("another port should be another finding, got ports %v", ports)
	}

	// The API read path returns it.
	f, err := postgres.NewFindingRepository(db).GetByFingerprint(ctx, tn.tenant, got.fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if n := f.Network(); n.Port != 8443 || n.Transport != "tcp" || n.Service != "https" {
		t.Fatalf("repository read network = %+v", n)
	}
}
