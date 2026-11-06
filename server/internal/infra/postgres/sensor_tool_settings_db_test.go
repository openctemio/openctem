package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"testing"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/testdb"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

const testSettingsDigest = "sha256:0000000000000000000000000000000000000000000000000000000000000001"

// TestSensorToolSettings_TenantIsolation: a tenant reads, replaces and
// deletes only its own sensors' tool settings; a row can never be written
// for another tenant's sensor or a platform sensor; deleting the sensor
// deletes its settings.
func TestSensorToolSettings_TenantIsolation(t *testing.T) {
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping schema-level check")
	}
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()
	ctx := context.Background()
	if err := db.PingContext(ctx); err != nil {
		t.Skipf("cannot reach DATABASE_URL: %v", err)
	}

	seedTenant := func(name string) shared.ID {
		id := shared.NewID()
		if _, err := db.ExecContext(ctx, `INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $3)`,
			id.String(), name, name+"-"+id.String()[28:]); err != nil {
			t.Fatalf("seed tenant: %v", err)
		}
		t.Cleanup(func() { _, _ = db.ExecContext(ctx, `DELETE FROM tenants WHERE id = $1`, id.String()) })
		return id
	}
	tenantA, tenantB := seedTenant("tts-a"), seedTenant("tts-b")

	repo := NewSensorRepository(&DB{DB: db})
	newSensor := func(tenant shared.ID, name string) *sensordom.Sensor {
		a, err := sensordom.NewSensor(tenant, name, sensordom.SensorTypeWorker, "", nil, sensordom.ExecutionModeStandalone)
		if err != nil {
			t.Fatalf("new sensor: %v", err)
		}
		a.SetAPIKey("hash-"+a.ID.String(), "octs_"+a.ID.String()[:7])
		if err := repo.Create(ctx, a); err != nil {
			t.Fatalf("create sensor: %v", err)
		}
		return a
	}
	sA := newSensor(tenantA, "tts-sensor-a")

	in := sensordom.ToolSettings{
		TenantID: tenantA, SensorID: sA.ID, Tool: "nuclei",
		Values:       map[string]any{"rate_limit": json.Number("300")},
		SchemaDigest: testSettingsDigest,
	}
	if err := repo.SaveToolSettings(ctx, in); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, err := repo.GetToolSettings(ctx, tenantA, sA.ID, "nuclei")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Values["rate_limit"] != json.Number("300") || got.SchemaDigest != testSettingsDigest || got.TenantID != tenantA {
		t.Fatalf("round trip = %+v", got)
	}

	// Replace.
	in.Values = map[string]any{"rate_limit": json.Number("50")}
	if err := repo.SaveToolSettings(ctx, in); err != nil {
		t.Fatalf("replace: %v", err)
	}
	if got, _ := repo.GetToolSettings(ctx, tenantA, sA.ID, "nuclei"); got.Values["rate_limit"] != json.Number("50") {
		t.Fatalf("not replaced: %+v", got.Values)
	}

	// Tenant B sees nothing of tenant A's sensor.
	if _, err := repo.GetToolSettings(ctx, tenantB, sA.ID, "nuclei"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant get: %v", err)
	}
	if list, err := repo.ListToolSettings(ctx, tenantB, sA.ID); err != nil || len(list) != 0 {
		t.Fatalf("cross-tenant list = %v, %v", list, err)
	}
	if ok, err := repo.DeleteToolSettings(ctx, tenantB, sA.ID, "nuclei"); err != nil || ok {
		t.Fatalf("cross-tenant delete = %v, %v", ok, err)
	}
	// Tenant B cannot write onto tenant A's sensor: neither a new tool (the
	// foreign key) nor the existing row (the upsert's tenant guard).
	if err := repo.SaveToolSettings(ctx, sensordom.ToolSettings{TenantID: tenantB, SensorID: sA.ID, Tool: "httpx",
		Values: map[string]any{}, SchemaDigest: testSettingsDigest}); err == nil {
		t.Fatal("tenant B wrote settings on tenant A's sensor")
	}
	if err := repo.SaveToolSettings(ctx, sensordom.ToolSettings{TenantID: tenantB, SensorID: sA.ID, Tool: "nuclei",
		Values: map[string]any{"rate_limit": json.Number("9999")}, SchemaDigest: testSettingsDigest}); err == nil {
		t.Fatal("tenant B replaced tenant A's settings")
	}
	if got, _ := repo.GetToolSettings(ctx, tenantA, sA.ID, "nuclei"); got.Values["rate_limit"] != json.Number("50") {
		t.Fatalf("tenant A's row changed: %+v", got.Values)
	}
	if list, err := repo.ListToolSettings(ctx, tenantA, sA.ID); err != nil || len(list) != 1 {
		t.Fatalf("list = %v, %v", list, err)
	}

	// Delete, then a second delete reports nothing deleted.
	if ok, err := repo.DeleteToolSettings(ctx, tenantA, sA.ID, "nuclei"); err != nil || !ok {
		t.Fatalf("delete = %v, %v", ok, err)
	}
	if ok, _ := repo.DeleteToolSettings(ctx, tenantA, sA.ID, "nuclei"); ok {
		t.Fatal("second delete reported a row")
	}

	// Deleting the sensor deletes its settings.
	in.Tool = "httpx"
	if err := repo.SaveToolSettings(ctx, in); err != nil {
		t.Fatalf("save httpx: %v", err)
	}
	if _, err := db.ExecContext(ctx, `DELETE FROM sensors WHERE id = $1`, sA.ID.String()); err != nil {
		t.Fatalf("delete sensor: %v", err)
	}
	var n int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM sensor_tool_settings WHERE sensor_id = $1`, sA.ID.String()).Scan(&n); err != nil || n != 0 {
		t.Fatalf("settings left after the sensor: %d, %v", n, err)
	}
}
