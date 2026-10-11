package integration

// Reports arrive out of order (RFC-005 queue, sensor retries, quarantined
// reports accepted later). Ingest keeps the newer observation whatever the
// arrival order (RFC-069 §5.6): last_seen and the property merge follow the
// report's timestamp, a delayed older port scan never closes a port a newer
// one saw open, and a re-observed stale asset is saved active.

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestIngest_ObservationOrder(t *testing.T) {
	r := newV2RigWith(t, ingest.DefaultBlindingGuard(), func(svc *ingest.Service, db *postgres.DB) {
		wireSetReconciliation(svc, db)
	})
	tn := r.newTenant("naabu", "httpx")
	ctx := context.Background()
	tid := tn.tenant
	agt := &sensor.Sensor{ID: tn.sensor, TenantID: &tid, Type: sensor.SensorTypeWorker, Status: sensor.SensorStatusActive}
	send := func(tool string, observed time.Time, bind ingest.Binding, a ctis.Asset) {
		t.Helper()
		rep := &ctis.Report{Version: "1.0", Tool: &ctis.Tool{Name: tool}, Assets: []ctis.Asset{a},
			Metadata: ctis.ReportMetadata{ID: "rep-" + shared.NewID().String(), Timestamp: observed}}
		out, err := r.svc.Ingest(ctx, agt, ingest.Input{Report: rep, Options: ingest.Options{Binding: bind}})
		if err != nil || len(out.Errors) > 0 {
			t.Fatalf("Ingest: %v %v", err, out.Errors)
		}
	}
	now := time.Now().UTC()

	t.Run("properties and last_seen keep the newer observation", func(t *testing.T) {
		const name = "web.order.example.com"
		bind := ingest.Binding{Kind: ingest.BindingCommand, Targets: []string{name}, Tool: "httpx"}
		send("httpx", now.Add(-time.Hour), bind, ctis.Asset{ID: "w", Type: ctis.AssetTypeDomain, Value: name,
			Properties: ctis.Properties{"title": "New portal"}})
		// Delivered later, observed earlier.
		send("httpx", now.Add(-5*time.Hour), bind, ctis.Asset{ID: "w", Type: ctis.AssetTypeDomain, Value: name,
			Properties: ctis.Properties{"title": "Old portal", "x_note": "filled"}})
		var title, code string
		var lastSeen time.Time
		if err := r.db.QueryRowContext(ctx, `SELECT properties->>'title', COALESCE(properties->>'x_note', ''), last_seen
			FROM assets WHERE tenant_id = $1 AND name = $2`, tid.String(), name).Scan(&title, &code, &lastSeen); err != nil {
			t.Fatal(err)
		}
		if title != "New portal" {
			t.Errorf("title = %q: an older report overwrote a newer value", title)
		}
		if code != "filled" {
			t.Errorf("x_note = %q: an older report must still fill a gap", code)
		}
		if d := lastSeen.Sub(now.Add(-time.Hour)); d < -time.Second || d > time.Second {
			t.Errorf("last_seen = %s, want the newer observation %s", lastSeen, now.Add(-time.Hour))
		}
	})

	t.Run("a re-observed stale asset is active again", func(t *testing.T) {
		const name = "stale.order.example.com"
		bind := ingest.Binding{Kind: ingest.BindingCommand, Targets: []string{name}, Tool: "httpx"}
		send("httpx", now.Add(-time.Minute), bind, ctis.Asset{ID: "s", Type: ctis.AssetTypeDomain, Value: name})
		if _, err := r.db.ExecContext(ctx, `UPDATE assets SET status = 'stale' WHERE tenant_id = $1 AND name = $2`, tid.String(), name); err != nil {
			t.Fatal(err)
		}
		send("httpx", now, bind, ctis.Asset{ID: "s", Type: ctis.AssetTypeDomain, Value: name})
		var status string
		_ = r.db.QueryRowContext(ctx, `SELECT status FROM assets WHERE tenant_id = $1 AND name = $2`, tid.String(), name).Scan(&status)
		if status != "active" {
			t.Errorf("status = %s after a re-scan, want active", status)
		}
	})

	t.Run("a delayed older port scan never closes a newer open port", func(t *testing.T) {
		const ip = "203.0.113.91"
		bind := ingest.Binding{Kind: ingest.BindingCommand, Targets: []string{ip}, Tool: "naabu"}
		scan := func(observed time.Time, ports ...int) {
			t.Helper()
			list := make([]ctis.PortInfo, 0, len(ports))
			for _, p := range ports {
				list = append(list, ctis.PortInfo{Port: p, Protocol: "tcp", State: "open"})
			}
			send("naabu", observed, bind, ctis.Asset{ID: "ip", Type: ctis.AssetTypeIPAddress, Value: ip,
				Technical: &ctis.AssetTechnical{IPAddress: &ctis.IPAddressTechnical{Ports: list}}})
		}
		active := func() int {
			var n int
			_ = r.db.QueryRowContext(ctx, `SELECT count(*) FROM assets WHERE tenant_id = $1 AND sub_type = 'open_port'
				AND name LIKE $2 AND status = 'active'`, tid.String(), ip+"%").Scan(&n)
			return n
		}
		scan(now.Add(-time.Minute), 80, 443)
		if got := active(); got != 2 {
			t.Fatalf("after the first scan: %d active ports", got)
		}
		scan(now.Add(-3*time.Hour), 80) // observed before the first, delivered after
		if got := active(); got != 2 {
			t.Errorf("a delayed older scan closed a port a newer scan saw open: %d active", got)
		}
		scan(now, 80) // newer: 443 is closed now
		if got := active(); got != 1 {
			t.Errorf("a newer scan did not close the port: %d active", got)
		}
	})
}
