package routes

// A command-bound sensor report over the real v2 routes and ingest worker
// (docs/architecture/sensor-result-binding.md, "Hostname-scoped jobs";
// docs/architecture/sensor-platform-workflow.md): the platform, not the
// report, names the findings' channel, and a report of a hostname-scoped
// job creates nothing outside the job's targets. Requires DATABASE_URL.

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/command"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// heldReconCommand creates a subfinder scan command of tenantID for root,
// claimed and running for sensorID under lease epoch 1.
func (h *ctlHarness) heldReconCommand(tenantID, sensorID, root string) string {
	h.t.Helper()
	c, err := h.cmds.Create(context.Background(), command.CreateInput{TenantID: tenantID, SensorID: sensorID,
		Type: "scan", Priority: "normal", Payload: json.RawMessage(fmt.Sprintf(`{"scanner":"subfinder","targets":[%q]}`, root)), ExpiresIn: 3600})
	if err != nil {
		h.t.Fatalf("create command: %v", err)
	}
	if _, err := h.db.ExecContext(context.Background(), `
		UPDATE commands SET status = 'running', sensor_id = $2, lease_epoch = 1, acknowledged_at = now(),
		       started_at = now(), lease_expires_at = now() + interval '10 minutes'
		WHERE id = $1`, c.ID.String(), sensorID); err != nil {
		h.t.Fatalf("hold command: %v", err)
	}
	return c.ID.String()
}

func (h *ctlHarness) assetCount(tenantID, name string) int {
	h.t.Helper()
	var n int
	if err := h.db.QueryRowContext(context.Background(),
		`SELECT count(*) FROM assets WHERE tenant_id = $1 AND name = $2`, tenantID, name).Scan(&n); err != nil {
		h.t.Fatal(err)
	}
	return n
}

func TestSensorResults_ChannelAndJobTargetsArePlatformAssigned(t *testing.T) {
	h := newCtlHarness(t)
	s := h.newLimitedSensor(h.tenantID, "recon", []string{"subfinder"}, []string{"subdomain"}, 2)
	h.verifyTools(s)
	label := "jb" + shared.NewID().String()[:8]
	root := label + ".example.com"
	sub := "api." + root
	evil := label + "-victim.example.org"

	// Tenant B already has an asset of the out-of-bounds name: it must not
	// be touched by tenant A's report.
	tenantB := h.newTenant()
	if _, err := h.db.ExecContext(context.Background(), `
		INSERT INTO assets (id, tenant_id, name, asset_type, criticality, status, scope, exposure, last_seen, first_seen)
		VALUES ($1, $2, $3, 'domain', 'low', 'active', 'external', 'unknown', now() - interval '3 days', now() - interval '3 days')`,
		shared.NewID().String(), tenantB, evil); err != nil {
		t.Fatalf("seed tenant B asset: %v", err)
	}
	var seenB time.Time
	if err := h.db.QueryRowContext(context.Background(), `SELECT last_seen FROM assets WHERE tenant_id = $1 AND name = $2`,
		tenantB, evil).Scan(&seenB); err != nil {
		t.Fatal(err)
	}

	cmd := h.heldReconCommand(h.tenantID, s.id, root)
	body := []byte(fmt.Sprintf(`{"version":"1.4","metadata":{"timestamp":%q,"source_type":"manual"},`+
		`"tool":{"name":"subfinder"},"assets":[`+
		`{"id":"root","type":"domain","value":%q},{"id":"sub","type":"subdomain","value":%q},{"id":"evil","type":"domain","value":%q}],`+
		`"findings":[{"type":"misconfiguration","title":"planted on a host outside the job","severity":"high","rule_id":"jb-evil-%s","asset_ref":"evil"},`+
		`{"type":"misconfiguration","title":"on the target","severity":"low","rule_id":"jb-sub-%s","asset_ref":"sub"}]}`,
		time.Now().UTC().Format(time.RFC3339), root, sub, evil, label, label))
	rid := newReportID()
	resp, raw := h.putBound(s.key, cmd, rid, 1, body)
	h.want(resp, raw, 202, "")
	h.processReports(s.id)

	if h.assetCount(h.tenantID, root) != 1 || h.assetCount(h.tenantID, sub) != 1 {
		t.Fatalf("assets inside the job's targets were not created")
	}
	if n := h.assetCount(h.tenantID, evil); n != 0 {
		t.Fatalf("a host outside the job's targets was created (%d)", n)
	}
	if n := h.findingsAnywhere("jb-evil-" + label); n != 0 {
		t.Fatalf("%d findings on a host outside the job's targets were stored", n)
	}
	var channel string
	if err := h.db.QueryRowContext(context.Background(),
		`SELECT COALESCE(ingest_channel::text, '') FROM findings WHERE tenant_id = $1 AND rule_id = $2`,
		h.tenantID, "jb-sub-"+label).Scan(&channel); err != nil {
		t.Fatalf("finding on the target: %v", err)
	}
	if channel != "scanner" {
		t.Fatalf("ingest_channel %q: a sensor chose its own label; want scanner", channel)
	}

	var seenAfter time.Time
	var nB int
	if err := h.db.QueryRowContext(context.Background(), `SELECT count(*), max(last_seen) FROM assets WHERE tenant_id = $1 AND name = $2`,
		tenantB, evil).Scan(&nB, &seenAfter); err != nil {
		t.Fatal(err)
	}
	if nB != 1 || !seenAfter.Equal(seenB) {
		t.Fatalf("tenant B's asset changed: count %d, last_seen %v -> %v", nB, seenB, seenAfter)
	}

	// The drop is in tenant A's audit log (written asynchronously).
	deadline := time.Now().Add(5 * time.Second)
	for {
		var n int
		if err := h.db.QueryRowContext(context.Background(),
			`SELECT count(*) FROM audit_logs WHERE tenant_id = $1 AND action = 'sensor.results_outside_job' AND resource_id = $2`,
			h.tenantID, s.id).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("audit rows for the drop: %d, want 1", n)
		}
		time.Sleep(50 * time.Millisecond)
	}
	var nOther int
	if err := h.db.QueryRowContext(context.Background(),
		`SELECT count(*) FROM audit_logs WHERE tenant_id = $1 AND action = 'sensor.results_outside_job'`, tenantB).Scan(&nOther); err != nil {
		t.Fatal(err)
	}
	if nOther != 0 {
		t.Fatalf("tenant B got %d audit rows for tenant A's report", nOther)
	}
}
