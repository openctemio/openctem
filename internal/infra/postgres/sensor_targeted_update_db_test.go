package postgres

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	_ "github.com/lib/pq"

	"github.com/openctemio/api/pkg/domain/sensor"
	"github.com/openctemio/api/pkg/domain/shared"
)

// TestSensorTargetedUpdates_ExecuteAgainstSchema runs the targeted heartbeat and
// API-key UPDATEs against the real schema with random ids, so they match and
// mutate nothing while the SQL (column names, the uuid cast on the nullable
// tenant parameter, the status guard) is parsed, planned and executed for real.
//
// Skipped unless DATABASE_URL is set.
func TestSensorTargetedUpdates_ExecuteAgainstSchema(t *testing.T) {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping DB execution check")
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

	repo := NewSensorRepository(&DB{DB: db})
	tid := shared.NewID()

	for _, tenant := range []*shared.ID{&tid, nil} {
		ok, err := repo.UpdateHeartbeat(ctx, shared.NewID(), sensor.HeartbeatUpdate{
			TenantID: tenant, Version: "1.0.0", CPUPercent: 1, LoadScore: 2,
		})
		if err != nil {
			t.Fatalf("UpdateHeartbeat (tenant=%v) failed against schema: %v", tenant, err)
		}
		if ok {
			t.Fatal("random agent id must match no row")
		}
	}

	exp := time.Now().Add(time.Hour)
	for _, requireActive := range []bool{true, false} {
		ok, err := repo.UpdateAPIKey(ctx, shared.NewID(), "hash", "rda_x", &exp, requireActive)
		if err != nil {
			t.Fatalf("UpdateAPIKey (requireActive=%v) failed against schema: %v", requireActive, err)
		}
		if ok {
			t.Fatal("random agent id must match no row")
		}
	}
}
