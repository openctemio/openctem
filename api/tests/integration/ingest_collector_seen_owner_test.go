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
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// collectorRig is a v2 rig whose push gate and collector trust read the
// sensors' real grants.
func collectorRig(t *testing.T) *v2Rig {
	t.Helper()
	return newV2RigWith(t, ingest.DefaultBlindingGuard(), func(svc *ingest.Service, db *postgres.DB) {
		svc.SetGrants(postgres.NewSensorGrantRepository(db), nil)
	})
}

// addCollector adds a collector sensor to the tenant (the insert trigger
// gives it the collector grant) at the given trust level.
func (r *v2Rig) addCollector(tn v2Tenant, trust sensor.TrustLevel) shared.ID {
	r.t.Helper()
	id := shared.NewID()
	if _, err := r.db.ExecContext(context.Background(), `INSERT INTO sensors (id, tenant_id, name, api_key_hash, api_key_prefix, status, type)
		VALUES ($1, $2, $3, $4, 'octs_tst', 'active', 'collector')`,
		id.String(), tn.tenant.String(), "collector-"+id.String()[:8], "h-"+id.String()); err != nil {
		r.t.Fatalf("seed collector: %v", err)
	}
	if _, err := r.db.ExecContext(context.Background(), `UPDATE sensors SET trust_level = $2 WHERE id = $1`, id.String(), string(trust)); err != nil {
		r.t.Fatalf("set trust: %v", err)
	}
	return id
}

// collect ingests rep as an admitted unsolicited report of sensorID, for tenant.
func (r *v2Rig) collect(tenant, sensorID shared.ID, rep *ctis.Report) {
	r.t.Helper()
	tid := tenant
	agt := &sensor.Sensor{ID: sensorID, TenantID: &tid, Type: sensor.SensorTypeCollector, Status: sensor.SensorStatusActive}
	out, err := r.svc.Ingest(context.Background(), agt, ingest.Input{Report: rep, Options: ingest.Options{Admitted: true}})
	if err != nil {
		r.t.Fatalf("collector ingest: %v", err)
	}
	if len(out.Errors) > 0 {
		r.t.Fatalf("collector ingest: %v", out.Errors)
	}
}

func collectorReport(tool string, assets ...ctis.Asset) *ctis.Report {
	return &ctis.Report{Version: "1.0", Tool: &ctis.Tool{Name: tool},
		Metadata: ctis.ReportMetadata{Timestamp: time.Now().UTC(), SourceType: "collector", CoverageType: "full"}, Assets: assets}
}

// A source's per-asset last_seen is the asset's last-seen time: earlier
// than the report, never moved backwards, never reviving a stale asset; a
// future value counts as the report's time.
func TestIngest_CollectorLastSeen(t *testing.T) {
	r := collectorRig(t)
	ctx := context.Background()
	tn := r.newTenant()
	col := r.addCollector(tn, sensor.TrustNew)
	seen := func(lastSeen any) ctis.Asset {
		return ctis.Asset{ID: "h", Type: ctis.AssetTypeHost, Value: "web01.example.com", Name: "web01.example.com",
			Properties: ctis.Properties{"last_seen": lastSeen, "source_index": "os"}}
	}
	stored := func() (time.Time, string) {
		t.Helper()
		var at time.Time
		var status string
		if err := r.db.QueryRowContext(ctx, `SELECT last_seen, status FROM assets WHERE tenant_id = $1 AND name = 'web01.example.com'`,
			tn.tenant.String()).Scan(&at, &status); err != nil {
			t.Fatal(err)
		}
		return at, status
	}
	near := func(a, b time.Time) bool { d := a.Sub(b); return d < 2*time.Second && d > -2*time.Second }

	threeDays := time.Now().Add(-72 * time.Hour).UTC().Truncate(time.Second)
	r.collect(tn.tenant, col, collectorReport("splunk", seen(threeDays.Format(time.RFC3339))))
	if at, _ := stored(); !near(at, threeDays) {
		t.Fatalf("last_seen = %v, want the reported %v", at, threeDays)
	}

	// An older observation never moves it backwards.
	r.collect(tn.tenant, col, collectorReport("splunk", seen(float64(time.Now().Add(-240*time.Hour).Unix()))))
	if at, _ := stored(); !near(at, threeDays) {
		t.Fatalf("last_seen moved to %v, want it kept at %v", at, threeDays)
	}

	// An older observation never revives a stale asset.
	if _, err := r.db.ExecContext(ctx, `UPDATE assets SET status = 'stale' WHERE tenant_id = $1`, tn.tenant.String()); err != nil {
		t.Fatal(err)
	}
	r.collect(tn.tenant, col, collectorReport("splunk", seen(time.Now().Add(-100*time.Hour).Format(time.RFC3339))))
	if at, status := stored(); status != "stale" || !near(at, threeDays) {
		t.Fatalf("after an older observation: status %s last_seen %v, want stale at %v", status, at, threeDays)
	}

	// A time in the future is not believed: the report's time is used.
	if _, err := r.db.ExecContext(ctx, `UPDATE assets SET status = 'active' WHERE tenant_id = $1`, tn.tenant.String()); err != nil {
		t.Fatal(err)
	}
	r.collect(tn.tenant, col, collectorReport("splunk", seen(time.Now().Add(240*time.Hour).Format(time.RFC3339))))
	if at, _ := stored(); !near(at, time.Now()) {
		t.Fatalf("last_seen = %v after a future value, want about now", at)
	}
}

// Only a collector the tenant trusted is an integration source: its owner
// claim lands on the assets it creates. An untrusted collector's owner is
// dropped, and a collector of another tenant is never trusted for this one.
func TestIngest_TrustedCollectorOwner(t *testing.T) {
	r := collectorRig(t)
	ctx := context.Background()
	a := r.newTenant()
	b := r.newTenant()
	trusted := r.addCollector(a, sensor.TrustTrusted)
	untrusted := r.addCollector(a, sensor.TrustNew)

	pc := func(name string) ctis.Asset {
		return ctis.Asset{ID: name, Type: ctis.AssetTypeHost, Value: name, Name: name,
			Properties: ctis.Properties{"owner": "alice@example.com", "ad_object_guid": "6f9619ff-8b86-d011-b42d-00c04fc964ff"}}
	}
	ownerRef := func(tenant shared.ID, name string) string {
		t.Helper()
		var ref sql.NullString
		if err := r.db.QueryRowContext(ctx, `SELECT owner_ref FROM assets WHERE tenant_id = $1 AND name = $2`,
			tenant.String(), name).Scan(&ref); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		return ref.String
	}

	r.collect(a.tenant, trusted, collectorReport("ldap", pc("pc-trusted.corp.example.com")))
	if got := ownerRef(a.tenant, "pc-trusted.corp.example.com"); got != "alice@example.com" {
		t.Fatalf("trusted collector owner_ref = %q, want alice@example.com", got)
	}
	r.collect(a.tenant, untrusted, collectorReport("ldap", pc("pc-untrusted.corp.example.com")))
	if got := ownerRef(a.tenant, "pc-untrusted.corp.example.com"); got != "" {
		t.Fatalf("untrusted collector owner_ref = %q, want none", got)
	}
	// Tenant A's trusted collector reporting into tenant B is not trusted there.
	r.collect(b.tenant, trusted, collectorReport("ldap", pc("pc-cross.corp.example.com")))
	if got := ownerRef(b.tenant, "pc-cross.corp.example.com"); got != "" {
		t.Fatalf("another tenant's collector set owner_ref %q", got)
	}
}
