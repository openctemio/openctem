package sensor_test

// Heartbeat write cost on a seeded database (research/191 §4A.6): the
// Postgres row writes and WAL bytes per heartbeat. Opt-in, it runs alone:
//
//	OPENCTEM_HEARTBEAT_BENCH=1 OPENCTEM_HEARTBEAT_BENCH_MODE=redis \
//	  go test ./internal/app/sensor/ -run TestHeartbeatWriteCost -v
//
// A mixed fleet: 70 % idle, 30 % busy holding two running commands; every
// heartbeat moves the metrics (CPU), as a real one does. In redis mode the
// heartbeat history aggregates are flushed once, at the end (in service
// they are flushed every five minutes), so the count is an upper bound.

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strconv"
	"testing"
	"time"

	sensorapp "github.com/openctemio/openctem/api/internal/app/sensor"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type tableWrites struct{ upd, ins int64 }

func readWrites(t *testing.T, db *sql.DB) (map[string]tableWrites, int64) {
	t.Helper()
	ctx := context.Background()
	out := map[string]tableWrites{}
	rows, err := db.QueryContext(ctx, `SELECT relname, n_tup_upd, n_tup_ins FROM pg_stat_user_tables
		WHERE relname IN ('sensors', 'commands', 'sensor_heartbeat_history')`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		var w tableWrites
		if err := rows.Scan(&name, &w.upd, &w.ins); err != nil {
			t.Fatal(err)
		}
		out[name] = w
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	var lsn int64
	if err := db.QueryRowContext(ctx, `SELECT pg_wal_lsn_diff(pg_current_wal_lsn(), '0/0')::bigint`).Scan(&lsn); err != nil {
		t.Fatal(err)
	}
	return out, lsn
}

func TestHeartbeatWriteCost(t *testing.T) {
	if os.Getenv("OPENCTEM_HEARTBEAT_BENCH") != "1" {
		t.Skip("set OPENCTEM_HEARTBEAT_BENCH=1 to measure heartbeat write cost")
	}
	mode := os.Getenv("OPENCTEM_HEARTBEAT_BENCH_MODE")
	sensors, rounds := 500, 10
	if v, err := strconv.Atoi(os.Getenv("OPENCTEM_HEARTBEAT_BENCH_SENSORS")); err == nil && v > 0 {
		sensors = v
	}
	h := newActivityHarness(t)
	ctx := context.Background()
	db := &postgres.DB{DB: h.db}
	repo := postgres.NewSensorRepository(db)
	svc := sensorapp.NewSensorService(repo, nil, logger.NewNop())
	svc.SetHeartbeatHistory(postgres.NewSensorHeartbeatHistoryRepository(db))
	cmds := postgres.NewCommandRepository(db)
	svc.SetLeaseRenewer(cmds)
	benchConfigure(t, svc, repo, db, mode)

	tid := h.tenant()
	ids := make([]shared.ID, sensors)
	running := map[shared.ID][]string{}
	for i := range ids {
		ids[i] = h.sensor(tid)
		if i%10 < 3 {
			for j := 0; j < 2; j++ {
				cid := shared.NewID()
				h.exec(`INSERT INTO commands (id, tenant_id, type, status, sensor_id, lease_epoch, lease_expires_at, payload)
				        VALUES ($1, $2, 'scan', 'running', $3, 1, NOW() + interval '3 minutes', '{}'::jsonb)`,
					cid.String(), tid.String(), ids[i].String())
				running[ids[i]] = append(running[ids[i]], cid.String())
			}
		}
	}
	beat := func(round int) {
		for i, id := range ids {
			d := beatData("1.0.0", float64((i+round)%100))
			if r, ok := running[id]; ok {
				d.Running, d.RunningReported, d.AdvisedSeconds = r, true, 5
			}
			if err := svc.UpdateHeartbeat(ctx, id, d); err != nil {
				t.Fatal(err)
			}
		}
	}
	// Warm-up round: first heartbeats bring every sensor online.
	beat(0)
	time.Sleep(12 * time.Second) // let every backend flush its table stats
	before, lsn0 := readWrites(t, h.db)
	start := time.Now()
	for r := 1; r <= rounds; r++ {
		beat(r)
	}
	elapsed := time.Since(start)
	svc.FlushLiveness(ctx)
	time.Sleep(12 * time.Second)
	after, lsn1 := readWrites(t, h.db)

	beats := float64(sensors * rounds)
	var total int64
	for _, tbl := range []string{"sensors", "commands", "sensor_heartbeat_history"} {
		d := after[tbl].upd - before[tbl].upd + after[tbl].ins - before[tbl].ins
		total += d
		t.Logf("%-26s %8d row writes  %.3f per heartbeat", tbl, d, float64(d)/beats)
	}
	wal := lsn1 - lsn0
	t.Logf("mode=%s sensors=%d heartbeats=%d: %d row writes (%.3f per heartbeat), WAL %d bytes (%.0f per heartbeat), %.0f heartbeats/s",
		modeName(mode), sensors, int(beats), total, float64(total)/beats, wal, float64(wal)/beats, beats/elapsed.Seconds())
	fmt.Fprintf(os.Stderr, "BENCH mode=%s writes_per_beat=%.3f wal_per_beat=%.0f\n", modeName(mode), float64(total)/beats, float64(wal)/beats)
}

func modeName(m string) string {
	if m == "" {
		return "postgres"
	}
	return m
}
