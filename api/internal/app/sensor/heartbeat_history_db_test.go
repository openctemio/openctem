package sensor_test

import (
	"context"
	"sync"
	"testing"
	"time"

	sensorapp "github.com/openctemio/openctem/api/internal/app/sensor"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
)

type gapRecorder struct {
	mu   sync.Mutex
	gaps []time.Duration
	ints []time.Duration
}

func (g *gapRecorder) ObserveHeartbeatGap(gap, interval time.Duration) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.gaps, g.ints = append(g.gaps, gap), append(g.ints, interval)
}

// RFC-035 follow-ups, against a migrated database:
//   - every heartbeat lands in the sensor's 15-minute history bucket, with
//     the gap measured from the stored deadline (polls do not shorten it),
//     and feeds the gap metric;
//   - a heartbeat that arrives after its deadline made the sensor late
//     records one heartbeat_recovered activity entry; an on-time one does
//     not.
func TestSensorHeartbeatHistoryAndRecovery_DB(t *testing.T) {
	h := newActivityHarness(t)
	db := &postgres.DB{DB: h.db}
	history := postgres.NewSensorHeartbeatHistoryRepository(db)
	gaps := &gapRecorder{}
	h.svc.SetHeartbeatHistory(history)
	h.svc.SetHeartbeatGapObserver(gaps)

	tenant := h.tenant()
	id := h.sensor(tenant)
	ctx := context.Background()
	beat := func() {
		h.heartbeat(id, sensorapp.SensorHeartbeatData{Version: "1.0.0", Protocol: 2, AdvisedSeconds: 30, DoorbellAware: true,
			Control: &sensordom.ControlReport{IntervalSeconds: 30, LagMillis: 120, Failures: 2}})
	}

	beat() // first heartbeat: no previous one, no gap
	if len(gaps.gaps) != 0 {
		t.Fatalf("first heartbeat observed a gap: %v", gaps.gaps)
	}

	// On time: the previous heartbeat was 25 s ago (due 5 s from now).
	h.exec(`UPDATE sensors SET heartbeat_interval_seconds = 30, heartbeat_due_at = NOW() + INTERVAL '5 seconds' WHERE id = $1`, id.String())
	beat()
	if _, ok := h.events(tenant, id)[string(sensordom.EventHeartbeatRecovered)]; ok {
		t.Fatal("an on-time heartbeat recorded a recovery")
	}

	// Late: the previous heartbeat was 80 s ago (due 50 s ago, interval
	// 30 s, grace 10 s: late from 40 s ago until 20 s from now).
	h.exec(`UPDATE sensors SET heartbeat_interval_seconds = 30, heartbeat_due_at = NOW() - INTERVAL '50 seconds' WHERE id = $1`, id.String())
	beat()
	rec, ok := h.events(tenant, id)[string(sensordom.EventHeartbeatRecovered)]
	if !ok {
		t.Fatal("no heartbeat_recovered entry after a late heartbeat")
	}
	if rec.Details["was"] != "late" || rec.Category != sensordom.CategoryStatus {
		t.Fatalf("recovery entry: %+v", rec)
	}
	if g, _ := rec.Details["gap_seconds"].(float64); g < 75 || g > 90 {
		t.Fatalf("recovery gap_seconds = %v, want about 80", rec.Details["gap_seconds"])
	}

	// The metric saw both gaps, with the interval the sensor followed.
	if len(gaps.gaps) != 2 || gaps.gaps[0] < 20*time.Second || gaps.gaps[0] > 30*time.Second ||
		gaps.gaps[1] < 75*time.Second || gaps.gaps[1] > 90*time.Second || gaps.ints[1] != 30*time.Second {
		t.Fatalf("observed gaps %v intervals %v", gaps.gaps, gaps.ints)
	}

	// The history: three heartbeats in this bucket (or split across two at
	// a bucket boundary), the largest gap about 80 s, lag and failures from
	// the control report.
	buckets, err := h.svc.HeartbeatHistory(ctx, tenant.String(), id.String(), 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	var beats int
	var maxGap float64
	var failures, lag int64
	for _, b := range buckets {
		beats += b.Beats
		maxGap = max(maxGap, b.MaxGapSeconds)
		failures += b.Failures
		lag = max(lag, b.MaxLagMillis)
	}
	if beats != 3 || maxGap < 75 || maxGap > 90 || failures != 6 || lag != 120 {
		t.Fatalf("history %+v: beats %d max gap %.1f failures %d lag %d", buckets, beats, maxGap, failures, lag)
	}

	// Another tenant cannot read it.
	if _, err := h.svc.HeartbeatHistory(ctx, h.tenant().String(), id.String(), time.Hour); err == nil {
		t.Fatal("another tenant read the history")
	}

	// Retention: buckets older than 48 h go, recent ones stay.
	h.exec(`INSERT INTO sensor_heartbeat_history (sensor_id, tenant_id, bucket_start, beats) VALUES ($1, $2, NOW() - INTERVAL '3 days', 1)`,
		id.String(), tenant.String())
	n, err := history.DeleteHeartbeatHistoryBefore(ctx, time.Now().Add(-sensordom.HeartbeatHistoryRetention), 100)
	if err != nil || n < 1 {
		t.Fatalf("retention deleted %d: %v", n, err)
	}
	if left, _ := h.svc.HeartbeatHistory(ctx, tenant.String(), id.String(), 24*time.Hour); len(left) != len(buckets) {
		t.Fatalf("retention removed recent buckets: %d left of %d", len(left), len(buckets))
	}
}
