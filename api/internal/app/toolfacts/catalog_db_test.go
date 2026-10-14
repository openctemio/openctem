package toolfacts_test

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/app/toolfacts"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/stage"
)

func openDB(t *testing.T) *sql.DB {
	t.Helper()
	url := testdb.URL()
	if url == "" {
		t.Skip("DATABASE_URL not set")
	}
	db, err := sql.Open("postgres", url)
	if err != nil {
		t.Skip(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Ping(); err != nil {
		t.Skipf("cannot reach DATABASE_URL: %v", err)
	}
	return db
}

func exec(t *testing.T, db *sql.DB, q string, args ...any) {
	t.Helper()
	if _, err := db.ExecContext(context.Background(), q, args...); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
}

// reportTool stores a manifest for a new sensor of tenantID that reports
// tool with a contract implementing ref. platform: a platform sensor (its
// row names the operator's tenant).
func reportTool(t *testing.T, db *sql.DB, tenantID *shared.ID, platform bool, tool, ref string, descriptor string) {
	t.Helper()
	id := shared.NewID()
	if platform {
		exec(t, db, `INSERT INTO sensors (id, tenant_id, name, type, status, health, api_key_hash, api_key_prefix,
			execution_mode, max_concurrent_jobs, current_jobs, is_platform_sensor)
			VALUES ($1, $2, $3, 'worker', 'active', 'online', $4, $5, 'daemon', 5, 0, TRUE)`,
			id.String(), tenantID.String(), "facts-platform-"+id.String(), "hash-"+id.String(), id.String()[:8])
	} else {
		exec(t, db, `INSERT INTO sensors (id, tenant_id, name, type, status, health, api_key_hash, api_key_prefix,
			execution_mode, max_concurrent_jobs, current_jobs)
			VALUES ($1, $2, $3, 'worker', 'active', 'online', $4, $5, 'daemon', 5, 0)`,
			id.String(), tenantID.String(), "facts-"+id.String(), "hash-"+id.String(), id.String()[:8])
	}
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM sensors WHERE id = $1`, id.String()) })
	sum := sha256.Sum256([]byte(id.String()))
	c := &sensor.ToolContract{APIVersion: sensor.ToolContractAPIVersion, Digest: "sha256:" + hex.EncodeToString(sum[:]),
		Version: "1.0.0", Class: "target-scan", Tier: "T2", Implements: []string{ref}, Produces: []string{}}
	if descriptor != "" {
		c.Descriptor = json.RawMessage(descriptor)
	}
	m := sensor.Manifest{Schema: 1, Tools: []sensor.ManifestTool{{Name: tool, Installed: true, Contract: c}}}
	if _, err := postgres.NewSensorRepository(&postgres.DB{DB: db}).SaveManifest(context.Background(),
		sensor.ManifestVersion{SensorID: id, TenantID: tenantID, Digest: "sha256:" + hex.EncodeToString(sum[:]),
			Source: sensor.ManifestSourceSensor, Manifest: m}, nil, time.Now()); err != nil {
		t.Fatal(err)
	}
}

// SECURITY: a tool tenant B's sensor reports never appears in tenant A's
// catalog (nor A's in B's); a platform sensor's tool appears in both. The
// facts come from the stored manifests: tenant A's toyweb implements
// dast.web with its descriptor's param mapping.
func TestLoader_TenantIsolation_DB(t *testing.T) {
	db := openDB(t)
	a, b, owner := shared.NewID(), shared.NewID(), shared.NewID()
	for _, id := range []shared.ID{a, b, owner} {
		exec(t, db, `INSERT INTO tenants (id, name, slug) VALUES ($1, 'facts', $2)`, id.String(), "facts-"+id.String())
		tid := id
		t.Cleanup(func() {
			_, _ = db.Exec(`DELETE FROM sensors WHERE tenant_id = $1`, tid.String())
			_, _ = db.Exec(`DELETE FROM tenants WHERE id = $1`, tid.String())
		})
	}
	reportTool(t, db, &a, false, "toyweb", "dast.web@1", `{"implements":[{"capability":"dast.web@1","params":{"max_duration_minutes":{"key":"max_minutes"}}}]}`)
	reportTool(t, db, &b, false, "toolb", "crawl.web@1", "")
	plat := "plat-" + shared.NewID().String()[:8]
	reportTool(t, db, &owner, true, plat, "lookup.asn@1", "")

	l := toolfacts.New(postgres.NewSensorRepository(&postgres.DB{DB: db}))
	catA, err := l.Catalog(context.Background(), a)
	if err != nil {
		t.Fatal(err)
	}
	catB, err := l.Catalog(context.Background(), b)
	if err != nil {
		t.Fatal(err)
	}
	dast, _ := catA.Lookup(stage.DASTWeb)
	if dast.DefaultTool() != "toyweb" {
		t.Fatalf("tenant A dast.web tools = %v", dast.Tools())
	}
	if k, ok := dast.ToolParamKey("toyweb", "max_duration_minutes"); !ok || k != "max_minutes" {
		t.Fatalf("toyweb mapping %q %v", k, ok)
	}
	if len(catA.ForTool("toolb")) != 0 || len(catB.ForTool("toyweb")) != 0 {
		t.Fatal("one tenant's sensor tool reached the other tenant's catalog")
	}
	if len(catA.ForTool(plat)) != 1 || len(catB.ForTool(plat)) != 1 {
		t.Fatal("the platform sensor's tool is missing from a tenant's catalog")
	}
}
