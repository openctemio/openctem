package sensor_test

// Heartbeat soft state end to end (docs/architecture/sensors.md, "Heartbeat
// soft state"): real heartbeats through UpdateHeartbeat against a migrated
// database and a Redis liveness store. Requires DATABASE_URL and
// REDIS_HOST/REDIS_PORT (Redis database 13 is used and flushed).

import (
	"context"
	"database/sql"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	redislib "github.com/redis/go-redis/v9"

	sensorapp "github.com/openctemio/openctem/api/internal/app/sensor"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/infra/redis"
	"github.com/openctemio/openctem/api/internal/metrics"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func livenessRedis(t testing.TB) redislib.UniversalClient {
	t.Helper()
	host, port := os.Getenv("REDIS_HOST"), os.Getenv("REDIS_PORT")
	if host == "" || port == "" {
		t.Skip("REDIS_HOST/REDIS_PORT not set; skipping liveness store DB test")
	}
	rc := redislib.NewClient(&redislib.Options{Addr: net.JoinHostPort(host, port), Password: os.Getenv("REDIS_PASSWORD"), DB: 13})
	if err := rc.Ping(context.Background()).Err(); err != nil {
		t.Skipf("redis: %v", err)
	}
	t.Cleanup(func() { _ = rc.Close() })
	return rc
}

// redisService is a SensorService in redis mode on h's database (one API
// replica); the store is shared through rc.
func redisService(t *testing.T, h *activityHarness, store sensordom.LivenessStore) (*sensorapp.SensorService, *postgres.SensorRepository) {
	t.Helper()
	db := &postgres.DB{DB: h.db}
	repo := postgres.NewSensorRepository(db)
	repo.SetLivenessOverlay(store)
	svc := sensorapp.NewSensorService(repo, nil, logger.NewNop())
	svc.SetLiveness(sensordom.LivenessRedis, store, repo, postgres.NewSensorHeartbeatHistoryRepository(db))
	t.Cleanup(func() { svc.FlushLiveness(context.Background()) })
	return svc, repo
}

type rowState struct {
	health    string
	version   string
	updatedAt time.Time
	lastSeen  sql.NullTime
}

func readRow(t *testing.T, db *sql.DB, id shared.ID) rowState {
	t.Helper()
	var r rowState
	var v sql.NullString
	if err := db.QueryRowContext(context.Background(),
		`SELECT health, version, updated_at, last_seen_at FROM sensors WHERE id = $1`, id.String()).
		Scan(&r.health, &v, &r.updatedAt, &r.lastSeen); err != nil {
		t.Fatal(err)
	}
	r.version = v.String
	return r
}

func beatData(version string, cpu float64) sensorapp.SensorHeartbeatData {
	return sensorapp.SensorHeartbeatData{
		Version: version, Hostname: "scanner-1", CPUPercent: cpu, MemoryPercent: 40,
		IPAddress: "192.0.2.10", Protocol: 2, AdvisedSeconds: 30, DoorbellAware: true,
	}
}

func writes(kind string) float64 {
	return testutil.ToFloat64(metrics.SensorHeartbeatWritesTotal.WithLabelValues(kind))
}

// In redis mode a steady heartbeat writes nothing to Postgres; a change, or
// a sensor Postgres does not have online, is written at once; reads overlay
// the store's live deadline.
func TestLiveness_RedisMode_WritesOnlyOnChange_DB(t *testing.T) {
	h := newActivityHarness(t)
	store := redis.NewSensorLivenessStore(livenessRedis(t))
	svc, repo := redisService(t, h, store)
	tid := h.tenant()
	id := h.sensor(tid)
	ctx := context.Background()

	// First heartbeat: no entry yet, written (and brings it online).
	if err := svc.UpdateHeartbeat(ctx, id, beatData("1.0.0", 10)); err != nil {
		t.Fatal(err)
	}
	first := readRow(t, h.db, id)
	if first.health != "online" || first.version != "1.0.0" {
		t.Fatalf("first heartbeat not written: %+v", first)
	}

	// Steady heartbeats (only metrics move): no Postgres write.
	none := writes("none")
	for i := 0; i < 5; i++ {
		if err := svc.UpdateHeartbeat(ctx, id, beatData("1.0.0", float64(20+i))); err != nil {
			t.Fatal(err)
		}
	}
	if got := readRow(t, h.db, id); !got.updatedAt.Equal(first.updatedAt) {
		t.Fatalf("a steady heartbeat rewrote the sensors row (updated_at %v -> %v)", first.updatedAt, got.updatedAt)
	}
	if d := writes("none") - none; d != 5 {
		t.Fatalf("steady heartbeats counted as none: %v, want 5", d)
	}
	// The read overlays the live deadline.
	a, err := repo.GetByTenantAndID(ctx, tid, id)
	if err != nil {
		t.Fatal(err)
	}
	if a.LastSeenAt == nil || !first.lastSeen.Valid || !a.LastSeenAt.After(first.lastSeen.Time) {
		t.Fatalf("read did not overlay the store: last seen %v (row %v)", a.LastSeenAt, first.lastSeen)
	}

	// A version change is written at once.
	if err := svc.UpdateHeartbeat(ctx, id, beatData("1.1.0", 30)); err != nil {
		t.Fatal(err)
	}
	if got := readRow(t, h.db, id); got.version != "1.1.0" {
		t.Fatalf("version change not written: %+v", got)
	}

	// The controller moved it down the ladder in Postgres: the next
	// heartbeat writes it back online.
	h.exec(`UPDATE sensors SET health = 'late' WHERE id = $1`, id.String())
	if err := svc.UpdateHeartbeat(ctx, id, beatData("1.1.0", 31)); err != nil {
		t.Fatal(err)
	}
	if got := readRow(t, h.db, id); got.health != "online" {
		t.Fatalf("a late sensor's heartbeat did not bring it back online: %+v", got)
	}

	// A revoked sensor's heartbeat writes nothing, even when it changes
	// something (the guarded UPDATE).
	h.exec(`UPDATE sensors SET status = 'revoked' WHERE id = $1`, id.String())
	if err := svc.UpdateHeartbeat(ctx, id, beatData("9.9.9", 1)); err != nil {
		t.Fatal(err)
	}
	if got := readRow(t, h.db, id); got.version == "9.9.9" {
		t.Fatal("a revoked sensor's heartbeat was written")
	}
}

// Two API replicas, one sensor, concurrent heartbeats carrying the same
// change: the store decides once, so Postgres gets one write.
func TestLiveness_MultiReplica_OneWritePerChange_DB(t *testing.T) {
	h := newActivityHarness(t)
	store := redis.NewSensorLivenessStore(livenessRedis(t))
	a, _ := redisService(t, h, store)
	b, _ := redisService(t, h, store)
	id := h.sensor(h.tenant())
	ctx := context.Background()
	if err := a.UpdateHeartbeat(ctx, id, beatData("2.0.0", 1)); err != nil {
		t.Fatal(err)
	}
	full := writes("full")
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		svc := a
		if i%2 == 1 {
			svc = b
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = svc.UpdateHeartbeat(ctx, id, beatData("2.1.0", float64(i)))
		}()
	}
	wg.Wait()
	if d := writes("full") - full; d != 1 {
		t.Fatalf("Postgres writes for one change across two replicas: %v, want 1", d)
	}
	if got := readRow(t, h.db, id); got.version != "2.1.0" {
		t.Fatalf("change not written: %+v", got)
	}
}

// Store unreachable: heartbeats fall back to Postgres, at most one per
// sensor per minute; the rest are dropped (the health controller holds
// convictions meanwhile).
func TestLiveness_StoreDown_FallbackBounded_DB(t *testing.T) {
	h := newActivityHarness(t)
	dead := redislib.NewClient(&redislib.Options{Addr: "127.0.0.1:1", DialTimeout: 50 * time.Millisecond, MaxRetries: -1})
	t.Cleanup(func() { _ = dead.Close() })
	svc, _ := redisService(t, h, redis.NewSensorLivenessStore(dead))
	id := h.sensor(h.tenant())
	ctx := context.Background()
	fb, dropped := writes("fallback"), writes("dropped")
	for i := 0; i < 5; i++ {
		if err := svc.UpdateHeartbeat(ctx, id, beatData("3.0.0", float64(i))); err != nil {
			t.Fatal(err)
		}
	}
	if d := writes("fallback") - fb; d != 1 {
		t.Fatalf("fallback writes: %v, want 1", d)
	}
	if d := writes("dropped") - dropped; d != 4 {
		t.Fatalf("dropped heartbeats: %v, want 4", d)
	}
	if got := readRow(t, h.db, id); got.health != "online" || got.version != "3.0.0" {
		t.Fatalf("fallback heartbeat not written: %+v", got)
	}
}

// The batched checkpoint: one statement for many sensors, never moving
// last_seen_at back, never writing another tenant's or a revoked sensor's
// row, and far past the bind-parameter limit.
func TestLiveness_CheckpointBatch_DB(t *testing.T) {
	h := newActivityHarness(t)
	repo := postgres.NewSensorRepository(&postgres.DB{DB: h.db})
	ctx := context.Background()
	tid, other := h.tenant(), h.tenant()
	a, b, revoked := h.sensor(tid), h.sensor(tid), h.sensor(tid)
	h.exec(`UPDATE sensors SET status = 'revoked' WHERE id = $1`, revoked.String())
	seen := time.Now().UTC().Truncate(time.Microsecond)
	slots := &sensordom.LoadReport{Capacity: &sensordom.ReportedCapacity{SlotsTotal: 4, SlotsFree: 1}}
	rows := []sensordom.LivenessCheckpoint{
		{TenantID: &tid, SensorID: a, SeenAt: seen, DueAt: seen.Add(30 * time.Second), Interval: 30 * time.Second,
			Load: sensordom.LivenessLoad{CPUPercent: 42, Load: slots}},
		{TenantID: &other, SensorID: b, SeenAt: seen, DueAt: seen, Interval: time.Minute},     // wrong tenant
		{TenantID: &tid, SensorID: revoked, SeenAt: seen, DueAt: seen, Interval: time.Minute}, // revoked
	}
	// Padding far past 65,535 bind parameters if each value were one.
	for i := 0; i < 20000; i++ {
		rows = append(rows, sensordom.LivenessCheckpoint{TenantID: &tid, SensorID: shared.NewID(), SeenAt: seen, DueAt: seen})
	}
	n, err := repo.CheckpointLiveness(ctx, rows)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("rows written: %d, want 1 (only the active sensor of its own tenant)", n)
	}
	var cpu float64
	var due sql.NullTime
	var capa sql.NullString
	if err := h.db.QueryRowContext(ctx, `SELECT cpu_percent, heartbeat_due_at, reported_capacity::text FROM sensors WHERE id = $1`, a.String()).
		Scan(&cpu, &due, &capa); err != nil {
		t.Fatal(err)
	}
	if cpu != 42 || !due.Valid || !due.Time.Equal(seen.Add(30*time.Second)) || !capa.Valid {
		t.Fatalf("checkpoint row: cpu %v due %v capacity %v", cpu, due, capa)
	}
	// An older checkpoint (another replica flushing late) changes nothing.
	older := rows[0]
	older.SeenAt, older.Load.CPUPercent = seen.Add(-time.Minute), 1
	if n, err := repo.CheckpointLiveness(ctx, []sensordom.LivenessCheckpoint{older}); err != nil || n != 0 {
		t.Fatalf("an older checkpoint was written: %d %v", n, err)
	}
}

// The heartbeat history batch adds to what is stored (two replicas flushing
// the same bucket both count) and stays inside the tenant.
func TestLiveness_HistoryBatchAdditive_DB(t *testing.T) {
	h := newActivityHarness(t)
	hist := postgres.NewSensorHeartbeatHistoryRepository(&postgres.DB{DB: h.db})
	ctx := context.Background()
	tid := h.tenant()
	id := h.sensor(tid)
	bucket := sensordom.HeartbeatBucketStart(time.Now())
	agg := func(beats int64) sensordom.HeartbeatAggregate {
		return sensordom.HeartbeatAggregate{TenantID: tid, SensorID: id, BucketStart: bucket, Beats: beats, GapBeats: beats, SumGapSeconds: float64(beats) * 30, MaxGapSeconds: 31}
	}
	for _, n := range []int64{10, 7} {
		if err := hist.RecordHeartbeatBatch(ctx, []sensordom.HeartbeatAggregate{agg(n)}); err != nil {
			t.Fatal(err)
		}
	}
	got, err := hist.HeartbeatHistory(ctx, tid, id, bucket.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Beats != 17 {
		t.Fatalf("history: %+v, want one bucket of 17 beats", got)
	}
	// Another tenant cannot add to this sensor's bucket.
	other := h.tenant()
	bad := agg(100)
	bad.TenantID = other
	_ = hist.RecordHeartbeatBatch(ctx, []sensordom.HeartbeatAggregate{bad})
	got, _ = hist.HeartbeatHistory(ctx, tid, id, bucket.Add(-time.Hour))
	if len(got) != 1 || got[0].Beats != 17 {
		t.Fatalf("another tenant's batch changed the history: %+v", got)
	}
}
