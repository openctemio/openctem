package redis

// Heartbeat soft state (docs/architecture/sensors.md, "Heartbeat soft
// state"; research/191 §4A).
//
// Keys (the tenant is in every per-sensor key; shared sensors use the tenant
// "instance"; keys are built here from the authenticated principal, never
// from a request body):
//
//	oc:sl:{tenant}:{sensor}  hash: seen, due (ms), iv (s), dg (state digest),
//	                         ip, kip, kuse (key use), ckpt, judged
//	oc:sl:due                zset: member "{tenant}:{sensor}", score = due (ms)
//	oc:sl:gen                the store's generation (random), set on (re)build
//	oc:sl:grace              present while the cold-start grace runs
//
// Every time comes from the store's own clock (TIME), so all API replicas
// share one clock and a sensor's clock never matters. The due index is never
// scanned on the request path.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	redislib "github.com/redis/go-redis/v9"

	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

const (
	livenessPrefix   = "oc:sl:"
	livenessDueKey   = "oc:sl:due"
	livenessGenKey   = "oc:sl:gen"
	livenessGraceKey = "oc:sl:grace"
)

// livenessNowLua is the store's clock in milliseconds.
const livenessNowLua = `local t = redis.call('TIME')
local now = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
`

// beatScript records a heartbeat. KEYS: hash, due index. ARGV: member,
// interval (s), digest, ip, checkpoint period (ms), ttl (ms).
// Returns {changed, checkpoint, now, prev seen, prev due, prev iv, prev kuse}.
var beatScript = redislib.NewScript(livenessNowLua + `
local prev = redis.call('HMGET', KEYS[1], 'seen', 'due', 'iv', 'dg', 'ckpt', 'judged', 'kuse')
local iv = tonumber(ARGV[2])
local due = now + iv * 1000
local changed = 0
if prev[4] ~= ARGV[3] or prev[6] then changed = 1 end
local ckpt = tonumber(prev[5] or '0') or 0
local need = 0
if changed == 1 then
  ckpt = now
elseif now - ckpt >= tonumber(ARGV[5]) then
  need = 1
  ckpt = now
end
redis.call('HSET', KEYS[1], 'seen', now, 'due', due, 'iv', iv, 'dg', ARGV[3], 'ip', ARGV[4], 'ckpt', ckpt)
redis.call('HDEL', KEYS[1], 'judged')
redis.call('PEXPIRE', KEYS[1], ARGV[6])
redis.call('ZADD', KEYS[2], due, ARGV[1])
return {changed, need, now, prev[1] or '', prev[2] or '', prev[3] or '', prev[7] or ''}
`)

// touchScript records proof of life on an existing entry. KEYS: hash, due
// index. ARGV: member, ip ("" none), ttl (ms). Returns {exists, prev ip}.
var touchScript = redislib.NewScript(livenessNowLua + `
if redis.call('EXISTS', KEYS[1]) == 0 then return {0, ''} end
local v = redis.call('HMGET', KEYS[1], 'seen', 'due', 'iv', 'kip')
local seen = tonumber(v[1] or '0') or 0
if now > seen then redis.call('HSET', KEYS[1], 'seen', now) end
local iv = tonumber(v[3] or '0') or 0
if iv <= 0 then iv = 300 end
local due = math.max(tonumber(v[2] or '0') or 0, now + iv * 1000)
redis.call('ZADD', KEYS[2], due, ARGV[1])
local prev = v[4] or ''
if ARGV[2] ~= '' then redis.call('HSET', KEYS[1], 'kip', ARGV[2], 'kuse', now) end
redis.call('PEXPIRE', KEYS[1], ARGV[3])
return {1, prev}
`)

// judgeScript marks an entry judged while it was last seen at ARGV[1] (ms;
// "" when no entry is expected). KEYS: hash. Returns 1 when marked.
var judgeScript = redislib.NewScript(`
local seen = redis.call('HGET', KEYS[1], 'seen')
if not seen then
  if ARGV[1] == '' then return 1 end
  return 0
end
if seen ~= ARGV[1] then return 0 end
redis.call('HSET', KEYS[1], 'judged', '1')
return 1
`)

// seedScript rebuilds an entry unless it was seen later. KEYS: hash, due
// index. ARGV: member, seen, due (ms), iv (s), ttl (ms).
var seedScript = redislib.NewScript(`
local seen = tonumber(redis.call('HGET', KEYS[1], 'seen') or '0') or 0
if seen >= tonumber(ARGV[2]) then return 0 end
redis.call('HSET', KEYS[1], 'seen', ARGV[2], 'due', ARGV[3], 'iv', ARGV[4])
redis.call('PEXPIRE', KEYS[1], ARGV[5])
redis.call('ZADD', KEYS[2], ARGV[3], ARGV[1])
return 1
`)

// overdueScript lists due-index members due before now - ARGV[1] (ms),
// at most ARGV[2]. Returns {now, member, score, member, score, ...}.
var overdueScript = redislib.NewScript(livenessNowLua + `
local r = redis.call('ZRANGEBYSCORE', KEYS[1], '-inf', '(' .. (now - tonumber(ARGV[1])), 'WITHSCORES', 'LIMIT', 0, tonumber(ARGV[2]))
table.insert(r, 1, now)
return r
`)

// SensorLivenessStore is the Redis liveness store (sensor.LivenessStore).
type SensorLivenessStore struct {
	rdb redislib.UniversalClient
}

var _ sensor.LivenessStore = (*SensorLivenessStore)(nil)

// NewSensorLivenessStore builds the store on rdb.
func NewSensorLivenessStore(rdb redislib.UniversalClient) *SensorLivenessStore {
	return &SensorLivenessStore{rdb: rdb}
}

func livenessHashKey(k sensor.LivenessKey) string {
	return livenessPrefix + k.Tenant + ":" + k.Sensor.String()
}

func livenessMember(k sensor.LivenessKey) string {
	return k.Tenant + ":" + k.Sensor.String()
}

// parseLivenessMember is livenessMember's inverse.
func parseLivenessMember(m string) (sensor.LivenessKey, bool) {
	i := strings.LastIndexByte(m, ':')
	if i <= 0 {
		return sensor.LivenessKey{}, false
	}
	id, err := shared.IDFromString(m[i+1:])
	if err != nil {
		return sensor.LivenessKey{}, false
	}
	return sensor.LivenessKey{Tenant: m[:i], Sensor: id}, true
}

func unavailable(op string, err error) error {
	return fmt.Errorf("%w: %s: %w", sensor.ErrLivenessStoreUnavailable, op, err)
}

var livenessTTLms = strconv.FormatInt(sensor.LivenessEntryTTL.Milliseconds(), 10)

func msTime(v any) time.Time {
	var n int64
	switch x := v.(type) {
	case int64:
		n = x
	case string:
		if x == "" {
			return time.Time{}
		}
		f, err := strconv.ParseFloat(x, 64)
		if err != nil {
			return time.Time{}
		}
		n = int64(f)
	}
	if n <= 0 {
		return time.Time{}
	}
	return time.UnixMilli(n).UTC()
}

func secDuration(v any) time.Duration {
	s, _ := v.(string)
	n, err := strconv.Atoi(s)
	if err != nil || n <= 0 {
		return 0
	}
	return time.Duration(n) * time.Second
}

// Beat records a heartbeat.
func (s *SensorLivenessStore) Beat(ctx context.Context, b sensor.LivenessBeat) (sensor.LivenessBeatResult, error) {
	var res sensor.LivenessBeatResult
	iv := int64(sensor.ClampHeartbeatInterval(b.Interval) / time.Second)
	ckpt := b.CheckpointEvery
	if ckpt <= 0 {
		ckpt = sensor.LivenessCheckpointPeriod
	}
	raw, err := beatScript.Run(ctx, s.rdb, []string{livenessHashKey(b.Key), livenessDueKey},
		livenessMember(b.Key), iv, b.Digest, b.IP, ckpt.Milliseconds(), livenessTTLms).Slice()
	if err != nil {
		return res, unavailable("beat", err)
	}
	if len(raw) < 7 {
		return res, unavailable("beat", errors.New("short reply"))
	}
	changed, _ := raw[0].(int64)
	need, _ := raw[1].(int64)
	res.Changed, res.Checkpoint = changed == 1, need == 1
	res.Now = msTime(raw[2])
	res.Prev = sensor.LivenessSnapshot{SeenAt: msTime(raw[3]), DueAt: msTime(raw[4]), Interval: secDuration(raw[5]), KeyUsedAt: msTime(raw[6])}
	return res, nil
}

// Touch records proof of life on an existing entry.
func (s *SensorLivenessStore) Touch(ctx context.Context, k sensor.LivenessKey, ip string) (bool, string, error) {
	raw, err := touchScript.Run(ctx, s.rdb, []string{livenessHashKey(k), livenessDueKey}, livenessMember(k), ip, livenessTTLms).Slice()
	if err != nil {
		return false, "", unavailable("touch", err)
	}
	if len(raw) < 2 {
		return false, "", unavailable("touch", errors.New("short reply"))
	}
	exists, _ := raw[0].(int64)
	prev, _ := raw[1].(string)
	return exists == 1, prev, nil
}

// Invalidate forgets the stored digest.
func (s *SensorLivenessStore) Invalidate(ctx context.Context, k sensor.LivenessKey) error {
	if err := s.rdb.HDel(ctx, livenessHashKey(k), "dg").Err(); err != nil {
		return unavailable("invalidate", err)
	}
	return nil
}

// Snapshots reads entries in one pipeline.
func (s *SensorLivenessStore) Snapshots(ctx context.Context, keys []sensor.LivenessKey) (map[shared.ID]sensor.LivenessSnapshot, error) {
	out := make(map[shared.ID]sensor.LivenessSnapshot, len(keys))
	if len(keys) == 0 {
		return out, nil
	}
	pipe := s.rdb.Pipeline()
	cmds := make([]*redislib.SliceCmd, len(keys))
	for i, k := range keys {
		cmds[i] = pipe.HMGet(ctx, livenessHashKey(k), "seen", "due", "iv", "kuse")
	}
	if _, err := pipe.Exec(ctx); err != nil && !errors.Is(err, redislib.Nil) {
		return nil, unavailable("snapshots", err)
	}
	for i, c := range cmds {
		v, err := c.Result()
		if err != nil || len(v) < 4 || v[0] == nil {
			continue
		}
		snap := sensor.LivenessSnapshot{SeenAt: msTime(v[0]), DueAt: msTime(v[1]), Interval: secDuration(v[2]), KeyUsedAt: msTime(v[3])}
		if !snap.IsZero() {
			out[keys[i].Sensor] = snap
		}
	}
	return out, nil
}

// Overdue lists entries due before now - olderThan.
func (s *SensorLivenessStore) Overdue(ctx context.Context, olderThan time.Duration, limit int) (time.Time, []sensor.LivenessOverdue, error) {
	if limit <= 0 {
		limit = 2000
	}
	raw, err := overdueScript.Run(ctx, s.rdb, []string{livenessDueKey}, olderThan.Milliseconds(), limit).Slice()
	if err != nil {
		return time.Time{}, nil, unavailable("overdue", err)
	}
	if len(raw) == 0 {
		return time.Time{}, nil, unavailable("overdue", errors.New("empty reply"))
	}
	now := msTime(raw[0])
	out := make([]sensor.LivenessOverdue, 0, (len(raw)-1)/2)
	for i := 1; i+1 < len(raw); i += 2 {
		m, _ := raw[i].(string)
		k, ok := parseLivenessMember(m)
		if !ok {
			continue
		}
		out = append(out, sensor.LivenessOverdue{Key: k, DueAt: msTime(raw[i+1])})
	}
	return now, out, nil
}

// Judge marks an entry judged while it was last seen at seenAt.
func (s *SensorLivenessStore) Judge(ctx context.Context, k sensor.LivenessKey, seenAt time.Time) (bool, error) {
	seen := ""
	if !seenAt.IsZero() {
		seen = strconv.FormatInt(seenAt.UnixMilli(), 10)
	}
	n, err := judgeScript.Run(ctx, s.rdb, []string{livenessHashKey(k)}, seen).Int64()
	if err != nil {
		return false, unavailable("judge", err)
	}
	return n == 1, nil
}

// Unwatch removes sensors from the due index.
func (s *SensorLivenessStore) Unwatch(ctx context.Context, keys []sensor.LivenessKey) error {
	if len(keys) == 0 {
		return nil
	}
	members := make([]any, len(keys))
	for i, k := range keys {
		members[i] = livenessMember(k)
	}
	if err := s.rdb.ZRem(ctx, livenessDueKey, members...).Err(); err != nil {
		return unavailable("unwatch", err)
	}
	return nil
}

// Generation returns the store's generation, creating one when missing.
func (s *SensorLivenessStore) Generation(ctx context.Context) (string, bool, error) {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", false, fmt.Errorf("liveness generation: %w", err)
	}
	fresh := hex.EncodeToString(b[:])
	ok, err := s.rdb.SetNX(ctx, livenessGenKey, fresh, 0).Result()
	if err != nil {
		return "", false, unavailable("generation", err)
	}
	if ok {
		return fresh, true, nil
	}
	gen, err := s.rdb.Get(ctx, livenessGenKey).Result()
	if err != nil {
		return "", false, unavailable("generation", err)
	}
	return gen, false, nil
}

// Seed rebuilds entries in one pipeline.
func (s *SensorLivenessStore) Seed(ctx context.Context, seeds []sensor.LivenessSeed) error {
	const chunk = 500
	for start := 0; start < len(seeds); start += chunk {
		end := min(start+chunk, len(seeds))
		pipe := s.rdb.Pipeline()
		for _, sd := range seeds[start:end] {
			if sd.SeenAt.IsZero() {
				continue
			}
			due := sd.DueAt
			if due.Before(sd.SeenAt) {
				due = sd.SeenAt
			}
			iv := int64(sensor.ClampHeartbeatInterval(sd.Interval) / time.Second)
			// EVAL (not EVALSHA): a rebuild is rare and a fresh store has
			// no scripts loaded.
			seedScript.Eval(ctx, pipe, []string{livenessHashKey(sd.Key), livenessDueKey},
				livenessMember(sd.Key), sd.SeenAt.UnixMilli(), due.UnixMilli(), iv, livenessTTLms)
		}
		if _, err := pipe.Exec(ctx); err != nil && !errors.Is(err, redislib.Nil) {
			return unavailable("seed", err)
		}
	}
	return nil
}

// StartGrace starts the cold-start grace.
func (s *SensorLivenessStore) StartGrace(ctx context.Context, d time.Duration) error {
	if err := s.rdb.Set(ctx, livenessGraceKey, "1", d).Err(); err != nil {
		return unavailable("grace", err)
	}
	return nil
}

// InGrace reports whether the cold-start grace runs.
func (s *SensorLivenessStore) InGrace(ctx context.Context) (bool, error) {
	n, err := s.rdb.Exists(ctx, livenessGraceKey).Result()
	if err != nil {
		return false, unavailable("grace", err)
	}
	return n > 0, nil
}

// Watched counts the due index.
func (s *SensorLivenessStore) Watched(ctx context.Context) (int64, error) {
	n, err := s.rdb.ZCard(ctx, livenessDueKey).Result()
	if err != nil {
		return 0, unavailable("watched", err)
	}
	return n, nil
}
