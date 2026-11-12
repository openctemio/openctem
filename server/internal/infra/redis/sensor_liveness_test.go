package redis

import (
	"context"
	"errors"
	"net"
	"os"
	"testing"
	"time"

	redislib "github.com/redis/go-redis/v9"

	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// livenessTestRedis is a client on a database of its own (14), so the
// FLUSHDB of the cold-start test never touches other packages' keys.
func livenessTestRedis(t *testing.T) redislib.UniversalClient {
	t.Helper()
	host := os.Getenv("REDIS_HOST")
	if host == "" {
		host = "localhost"
	}
	port := os.Getenv("REDIS_PORT")
	if port == "" {
		port = "6379"
	}
	rc := redislib.NewClient(&redislib.Options{Addr: net.JoinHostPort(host, port), Password: os.Getenv("REDIS_PASSWORD"), DB: 14})
	if err := rc.Ping(context.Background()).Err(); err != nil {
		t.Skipf("redis: %v", err)
	}
	t.Cleanup(func() { _ = rc.Close() })
	return rc
}

func beat(t *testing.T, s *SensorLivenessStore, k sensor.LivenessKey, digest string, every time.Duration) sensor.LivenessBeatResult {
	t.Helper()
	r, err := s.Beat(context.Background(), sensor.LivenessBeat{Key: k, Interval: 30 * time.Second, Digest: digest, IP: "192.0.2.1", CheckpointEvery: every})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// A heartbeat is "changed" (written to Postgres) only when there was no
// entry, the digest moved, or the health controller judged the sensor;
// otherwise it waits for the checkpoint period.
func TestSensorLiveness_BeatDecides(t *testing.T) {
	s := NewSensorLivenessStore(livenessTestRedis(t))
	ctx := context.Background()
	k := sensor.LivenessKey{Tenant: shared.NewID().String(), Sensor: shared.NewID()}

	if r := beat(t, s, k, "d1", time.Hour); !r.Changed || r.Checkpoint || !r.Prev.IsZero() {
		t.Fatalf("first beat: %+v", r)
	}
	r := beat(t, s, k, "d1", time.Hour)
	if r.Changed || r.Checkpoint {
		t.Fatalf("steady beat must write nothing: %+v", r)
	}
	if r.Prev.IsZero() || r.Prev.Interval != 30*time.Second || r.Now.Before(r.Prev.SeenAt) {
		t.Fatalf("previous entry: %+v", r.Prev)
	}
	if r := beat(t, s, k, "d2", time.Hour); !r.Changed {
		t.Fatal("a changed digest must be written")
	}
	time.Sleep(5 * time.Millisecond)
	if r := beat(t, s, k, "d2", time.Millisecond); r.Changed || !r.Checkpoint {
		t.Fatalf("past the checkpoint period: %+v", r)
	}

	// A judged sensor's next heartbeat is written (it moves back online in
	// Postgres), once.
	snaps, err := s.Snapshots(ctx, []sensor.LivenessKey{k})
	if err != nil {
		t.Fatal(err)
	}
	ok, err := s.Judge(ctx, k, snaps[k.Sensor].SeenAt)
	if err != nil || !ok {
		t.Fatalf("judge: %v %v", ok, err)
	}
	if r := beat(t, s, k, "d2", time.Hour); !r.Changed {
		t.Fatal("the heartbeat after a verdict must be written")
	}
	if r := beat(t, s, k, "d2", time.Hour); r.Changed {
		t.Fatal("only the first heartbeat after a verdict is written")
	}

	// A verdict on a sensor that heartbeated since is refused.
	if ok, err := s.Judge(ctx, k, snaps[k.Sensor].SeenAt.Add(-time.Second)); err != nil || ok {
		t.Fatalf("stale verdict accepted: %v %v", ok, err)
	}

	// Invalidate: the next heartbeat is written again.
	if err := s.Invalidate(ctx, k); err != nil {
		t.Fatal(err)
	}
	if r := beat(t, s, k, "d2", time.Hour); !r.Changed {
		t.Fatal("after Invalidate the heartbeat must be written")
	}
}

// Touch records proof of life only on an existing entry and reports the
// previous key-use address.
func TestSensorLiveness_Touch(t *testing.T) {
	s := NewSensorLivenessStore(livenessTestRedis(t))
	ctx := context.Background()
	k := sensor.LivenessKey{Tenant: shared.NewID().String(), Sensor: shared.NewID()}

	if exists, _, err := s.Touch(ctx, k, "198.51.100.1"); err != nil || exists {
		t.Fatalf("touch without entry: %v %v", exists, err)
	}
	if snaps, _ := s.Snapshots(ctx, []sensor.LivenessKey{k}); len(snaps) != 0 {
		t.Fatal("touch created an entry")
	}
	beat(t, s, k, "d", time.Hour)
	if exists, prev, err := s.Touch(ctx, k, "198.51.100.1"); err != nil || !exists || prev != "" {
		t.Fatalf("first touch: %v %q %v", exists, prev, err)
	}
	if _, prev, _ := s.Touch(ctx, k, "198.51.100.2"); prev != "198.51.100.1" {
		t.Fatalf("previous address: %q", prev)
	}
	snaps, err := s.Snapshots(ctx, []sensor.LivenessKey{k})
	if err != nil || snaps[k.Sensor].KeyUsedAt.IsZero() {
		t.Fatalf("key use not recorded: %+v %v", snaps, err)
	}
}

// Keys carry the tenant: the same sensor id under two tenants is two
// entries, and one tenant's heartbeat, touch or verdict never reaches the
// other's.
func TestSensorLiveness_TenantIsolation(t *testing.T) {
	s := NewSensorLivenessStore(livenessTestRedis(t))
	ctx := context.Background()
	id := shared.NewID()
	a := sensor.LivenessKey{Tenant: shared.NewID().String(), Sensor: id}
	b := sensor.LivenessKey{Tenant: shared.NewID().String(), Sensor: id}

	beat(t, s, a, "d", time.Hour)
	snaps, err := s.Snapshots(ctx, []sensor.LivenessKey{b})
	if err != nil {
		t.Fatal(err)
	}
	if len(snaps) != 0 {
		t.Fatal("tenant A's heartbeat is visible under tenant B")
	}
	if exists, _, _ := s.Touch(ctx, b, "203.0.113.9"); exists {
		t.Fatal("tenant B touched tenant A's entry")
	}
	if ok, _ := s.Judge(ctx, b, time.Now()); ok {
		t.Fatal("tenant B judged an entry it does not have")
	}
	if r := beat(t, s, a, "d", time.Hour); r.Changed {
		t.Fatal("tenant B's calls changed tenant A's entry")
	}
	if got := livenessHashKey(a); got != "oc:sl:"+a.Tenant+":"+id.String() {
		t.Fatalf("key layout: %s", got)
	}
	sk := sensor.LivenessKeyOf(nil, id)
	if sk.Tenant != sensor.SharedLivenessTenant {
		t.Fatalf("shared sensor tenant: %q", sk.Tenant)
	}
}

// The due index lists overdue sensors only; Unwatch removes them; a seed
// never overwrites a newer entry.
func TestSensorLiveness_OverdueSeedUnwatch(t *testing.T) {
	rc := livenessTestRedis(t)
	s := NewSensorLivenessStore(rc)
	ctx := context.Background()
	tenant := shared.NewID().String()
	late := sensor.LivenessKey{Tenant: tenant, Sensor: shared.NewID()}
	fresh := sensor.LivenessKey{Tenant: tenant, Sensor: shared.NewID()}
	old := time.Now().Add(-10 * time.Minute)
	if err := s.Seed(ctx, []sensor.LivenessSeed{
		{Key: late, SeenAt: old, DueAt: old.Add(30 * time.Second), Interval: 30 * time.Second},
	}); err != nil {
		t.Fatal(err)
	}
	beat(t, s, fresh, "d", time.Hour)
	// A seed older than the entry is ignored.
	if err := s.Seed(ctx, []sensor.LivenessSeed{{Key: fresh, SeenAt: old, DueAt: old, Interval: time.Minute}}); err != nil {
		t.Fatal(err)
	}
	snaps, _ := s.Snapshots(ctx, []sensor.LivenessKey{fresh, late})
	if time.Since(snaps[fresh.Sensor].SeenAt) > time.Minute {
		t.Fatalf("a seed overwrote a newer entry: %+v", snaps[fresh.Sensor])
	}
	if !snaps[late.Sensor].SeenAt.Equal(old.Truncate(time.Millisecond).UTC()) {
		t.Fatalf("seeded entry: %+v want seen %v", snaps[late.Sensor], old)
	}

	_, overdue, err := s.Overdue(ctx, 10*time.Second, 10000)
	if err != nil {
		t.Fatal(err)
	}
	found := map[shared.ID]bool{}
	for _, o := range overdue {
		found[o.Key.Sensor] = true
		if o.Key.Sensor == late.Sensor && o.Key.Tenant != tenant {
			t.Fatalf("member tenant: %+v", o.Key)
		}
	}
	if !found[late.Sensor] || found[fresh.Sensor] {
		t.Fatalf("overdue: late %v fresh %v", found[late.Sensor], found[fresh.Sensor])
	}
	if err := s.Unwatch(ctx, []sensor.LivenessKey{late}); err != nil {
		t.Fatal(err)
	}
	_, overdue, _ = s.Overdue(ctx, 10*time.Second, 10000)
	for _, o := range overdue {
		if o.Key.Sensor == late.Sensor {
			t.Fatal("unwatched sensor still overdue")
		}
	}
}

// The generation is created once; an emptied store (FLUSHDB, a restart
// without data) creates a new one, which the health controller treats as a
// cold start. The grace is shared through the store.
func TestSensorLiveness_GenerationAndGrace(t *testing.T) {
	rc := livenessTestRedis(t)
	s := NewSensorLivenessStore(rc)
	ctx := context.Background()
	if err := rc.FlushDB(ctx).Err(); err != nil {
		t.Fatal(err)
	}
	g1, created, err := s.Generation(ctx)
	if err != nil || !created || g1 == "" {
		t.Fatalf("first generation: %q %v %v", g1, created, err)
	}
	g2, created, err := s.Generation(ctx)
	if err != nil || created || g2 != g1 {
		t.Fatalf("second generation: %q %v %v", g2, created, err)
	}
	if in, _ := s.InGrace(ctx); in {
		t.Fatal("grace without StartGrace")
	}
	if err := s.StartGrace(ctx, time.Minute); err != nil {
		t.Fatal(err)
	}
	if in, _ := s.InGrace(ctx); !in {
		t.Fatal("grace not running")
	}
	if err := rc.FlushDB(ctx).Err(); err != nil {
		t.Fatal(err)
	}
	if g3, created, _ := s.Generation(ctx); !created || g3 == g1 {
		t.Fatalf("after FLUSHDB: %q %v", g3, created)
	}
}

// A store that cannot be reached fails every call with
// ErrLivenessStoreUnavailable.
func TestSensorLiveness_Unavailable(t *testing.T) {
	rc := redislib.NewClient(&redislib.Options{Addr: "127.0.0.1:1", DialTimeout: 100 * time.Millisecond, MaxRetries: -1})
	defer func() { _ = rc.Close() }()
	s := NewSensorLivenessStore(rc)
	_, err := s.Beat(context.Background(), sensor.LivenessBeat{Key: sensor.LivenessKey{Tenant: "t", Sensor: shared.NewID()}, Interval: time.Second})
	if err == nil {
		t.Fatal("beat on an unreachable store succeeded")
	}
	if !errors.Is(err, sensor.ErrLivenessStoreUnavailable) {
		t.Fatalf("error does not wrap ErrLivenessStoreUnavailable: %v", err)
	}
}

// The degraded marker is shared through the store, and lapses with its TTL.
func TestSensorLiveness_DegradedMarker(t *testing.T) {
	rc := livenessTestRedis(t)
	s := NewSensorLivenessStore(rc)
	ctx := context.Background()
	_ = rc.Del(ctx, livenessDegradedKey).Err()
	if d, err := s.Degraded(ctx); err != nil || d {
		t.Fatalf("degraded before any mark: %v %v", d, err)
	}
	if err := s.MarkDegraded(ctx, 300*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	// Another store instance (another replica) sees it.
	if d, err := NewSensorLivenessStore(rc).Degraded(ctx); err != nil || !d {
		t.Fatalf("marker not visible to another replica: %v %v", d, err)
	}
	time.Sleep(400 * time.Millisecond)
	if d, _ := s.Degraded(ctx); d {
		t.Fatal("marker did not lapse")
	}
}

// An evicting maxmemory-policy is reported; noeviction is not.
func TestEvictionPolicyWarning(t *testing.T) {
	rc := livenessTestRedis(t)
	ctx := context.Background()
	prev, err := rc.ConfigGet(ctx, "maxmemory-policy").Result()
	if err != nil {
		t.Skipf("CONFIG not available: %v", err)
	}
	t.Cleanup(func() { _ = rc.ConfigSet(ctx, "maxmemory-policy", prev["maxmemory-policy"]).Err() })
	if err := rc.ConfigSet(ctx, "maxmemory-policy", "allkeys-lru").Err(); err != nil {
		t.Skipf("CONFIG SET not available: %v", err)
	}
	if w := EvictionPolicyWarning(ctx, rc); w == "" {
		t.Fatal("allkeys-lru not reported")
	}
	if err := rc.ConfigSet(ctx, "maxmemory-policy", "noeviction").Err(); err != nil {
		t.Fatal(err)
	}
	if w := EvictionPolicyWarning(ctx, rc); w != "" {
		t.Fatalf("noeviction reported: %s", w)
	}
}
