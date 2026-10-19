package sensor

// Heartbeat soft state (docs/architecture/sensors.md, "Heartbeat soft
// state"). The liveness store keeps what changes on every heartbeat (when it
// was seen, when the next one is due, the interval, the latest load) out of
// Postgres: Postgres gets state changes as they happen and a batched
// checkpoint every few minutes.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// LivenessMode says where heartbeat liveness lives (SENSOR_LIVENESS_STORE).
type LivenessMode string

const (
	// LivenessPostgres writes every heartbeat to Postgres, as before the
	// liveness store. The store is not used.
	LivenessPostgres LivenessMode = "postgres"
	// LivenessShadow writes every heartbeat to Postgres and to the store,
	// and the health controller counts where the two verdicts differ
	// (sensor_liveness_disagreements_total). Postgres decides.
	LivenessShadow LivenessMode = "shadow"
	// LivenessRedis keeps liveness in the store: Postgres gets state changes
	// and checkpoints only, and the health controller judges from the store.
	LivenessRedis LivenessMode = "redis"
)

// ParseLivenessMode reads a SENSOR_LIVENESS_STORE value; "" is shadow.
func ParseLivenessMode(s string) (LivenessMode, error) {
	switch m := LivenessMode(strings.ToLower(strings.TrimSpace(s))); m {
	case "":
		return LivenessShadow, nil
	case LivenessPostgres, LivenessShadow, LivenessRedis:
		return m, nil
	}
	return "", fmt.Errorf("%w: SENSOR_LIVENESS_STORE must be postgres, shadow or redis, not %q", shared.ErrValidation, s)
}

// Liveness store timing.
const (
	// LivenessCheckpointPeriod is how often a steady sensor's liveness and
	// load reach Postgres (±10 % jitter per heartbeat).
	LivenessCheckpointPeriod = 10 * time.Minute
	// LivenessColdStartGrace is how long the health controller convicts
	// nobody after the store came back empty or unreachable: twice the
	// longest interval the doorbell advises with the default lease (60 s),
	// so a sensor that follows the advice has heartbeated into the rebuilt
	// store before anyone is judged. The rebuild also sets every seeded
	// deadline to at least the end of the grace, and a sensor on a longer
	// interval has a proportionally longer road to offline (Ladder).
	LivenessColdStartGrace = 2 * time.Minute
	// LivenessEntryTTL bounds how long a silent sensor's entry stays in the
	// store (garbage collection only; never the liveness signal).
	LivenessEntryTTL = 3 * (MaxHeartbeatInterval + 3*MaxHeartbeatInterval)
)

// ErrLivenessStoreUnavailable: the store could not be reached.
var ErrLivenessStoreUnavailable = errors.New("sensor liveness store unavailable")

// SharedLivenessTenant is the tenant part of a shared sensor's keys: it has
// no organization (RFC-100).
const SharedLivenessTenant = "instance"

// LivenessKey names one sensor in the store. The tenant comes from the
// authenticated principal or the sensor row, never from a request body.
type LivenessKey struct {
	Tenant string
	Sensor shared.ID
}

// LivenessKeyOf is the store key of a sensor row.
func LivenessKeyOf(tenantID *shared.ID, sensorID shared.ID) LivenessKey {
	if tenantID == nil {
		return LivenessKey{Tenant: SharedLivenessTenant, Sensor: sensorID}
	}
	return LivenessKey{Tenant: tenantID.String(), Sensor: sensorID}
}

// LivenessBeat is one heartbeat as the store sees it.
type LivenessBeat struct {
	Key LivenessKey
	// Interval is the interval the sensor follows from now on.
	Interval time.Duration
	// Digest is the digest of what Postgres stores from a heartbeat besides
	// liveness and load (HeartbeatStateDigest): when it changes the
	// heartbeat is written to Postgres.
	Digest string
	// IP is the heartbeat's client address ("" unknown).
	IP string
	// CheckpointEvery is this heartbeat's checkpoint period (jittered).
	CheckpointEvery time.Duration
}

// LivenessBeatResult is what the store answers a heartbeat.
type LivenessBeatResult struct {
	// Now is the store's clock (one clock for every replica).
	Now time.Time
	// Changed: the digest differs from the stored one, there was no entry,
	// or the health controller judged the sensor since its last heartbeat.
	// The heartbeat must be written to Postgres.
	Changed bool
	// Checkpoint: nothing changed but the last checkpoint is older than the
	// period; the caller enqueues a checkpoint.
	Checkpoint bool
	// Prev is the entry before this heartbeat (zero when there was none).
	Prev LivenessSnapshot
}

// LivenessSnapshot is one sensor's entry.
type LivenessSnapshot struct {
	SeenAt   time.Time
	DueAt    time.Time
	Interval time.Duration
	// KeyUsedAt is the last key use recorded in the store (zero: none).
	KeyUsedAt time.Time
}

// IsZero reports whether there was no entry.
func (s LivenessSnapshot) IsZero() bool { return s.SeenAt.IsZero() }

// Deadline merges the entry into a stored deadline: the later of each.
// Postgres holds the last checkpoint or state change, the store the last
// heartbeat; whichever is newer counts (a heartbeat that fell back to
// Postgres while the store was unreachable is newer in Postgres).
func (s LivenessSnapshot) Deadline(stored HeartbeatDeadline) HeartbeatDeadline {
	if s.IsZero() {
		return stored
	}
	out := stored
	if out.LastSeenAt == nil || s.SeenAt.After(*out.LastSeenAt) {
		t := s.SeenAt
		out.LastSeenAt = &t
		if s.Interval > 0 {
			out.Interval = s.Interval
		}
	}
	if !s.DueAt.IsZero() && (out.DueAt == nil || s.DueAt.After(*out.DueAt)) {
		t := s.DueAt
		out.DueAt = &t
	}
	return out
}

// OverlayLiveness applies the store entry to a sensor read from Postgres, so
// every reader (API state, events, the ladder) sees the live deadline.
func (a *Sensor) OverlayLiveness(s LivenessSnapshot) {
	if a == nil || s.IsZero() {
		return
	}
	d := s.Deadline(a.HeartbeatDeadline())
	a.LastSeenAt, a.HeartbeatDueAt, a.HeartbeatInterval = d.LastSeenAt, d.DueAt, d.Interval
}

// LivenessOverdue is a store entry past its due time.
type LivenessOverdue struct {
	Key   LivenessKey
	DueAt time.Time
}

// LivenessSeed rebuilds one entry from Postgres after the store lost it.
type LivenessSeed struct {
	Key      LivenessKey
	SeenAt   time.Time
	DueAt    time.Time
	Interval time.Duration
}

// LivenessStore keeps heartbeat soft state. Implemented by
// redis.SensorLivenessStore. Every method fails with an error wrapping
// ErrLivenessStoreUnavailable when the store cannot be reached.
// LivenessDegradedTTL is how long one failed heartbeat write holds the
// health controller's convictions (see LivenessDegradedSignal).
const LivenessDegradedTTL = time.Minute

// LivenessDegradedSignal is the cross-replica "heartbeat writes are
// failing" marker. A replica that cannot record heartbeats (store or
// Postgres write failing) sets it; the health controller, which may run on
// another replica that reads the store fine, convicts nobody while it is
// set, because sensors that heartbeated to the failing replica look silent.
// The store implements it next to LivenessStore.
type LivenessDegradedSignal interface {
	// MarkDegraded sets the marker for ttl (setting it again extends it).
	MarkDegraded(ctx context.Context, ttl time.Duration) error
	// Degraded reports whether the marker is set.
	Degraded(ctx context.Context) (bool, error)
}

type LivenessStore interface {
	// Beat records a heartbeat (one atomic step on the store's clock).
	Beat(ctx context.Context, b LivenessBeat) (LivenessBeatResult, error)
	// Touch records proof of life without a heartbeat (a key use, a control
	// stream keepalive) on an existing entry. ip is the key use's address
	// ("" for none). exists is false when there is no entry (nothing
	// recorded); prevIP is the previous key-use address ("" none).
	Touch(ctx context.Context, k LivenessKey, ip string) (exists bool, prevIP string, err error)
	// Invalidate forgets the stored digest, so the next heartbeat is written
	// to Postgres (after a failed Postgres write).
	Invalidate(ctx context.Context, k LivenessKey) error
	// Snapshots reads the entries of keys; missing ones are absent.
	Snapshots(ctx context.Context, keys []LivenessKey) (map[shared.ID]LivenessSnapshot, error)
	// Overdue lists up to limit entries due before now - olderThan, and the
	// store's clock.
	Overdue(ctx context.Context, olderThan time.Duration, limit int) (time.Time, []LivenessOverdue, error)
	// Judge records that the health controller is moving the sensor down the
	// ladder, only while its entry was last seen at seenAt (zero: no entry
	// expected). A heartbeat after it is written to Postgres. ok is false
	// when the sensor heartbeated since.
	Judge(ctx context.Context, k LivenessKey, seenAt time.Time) (ok bool, err error)
	// Unwatch removes a sensor from the due index (it is offline or gone);
	// its entry stays until it expires.
	Unwatch(ctx context.Context, keys []LivenessKey) error
	// Generation returns the store's generation, creating one when there is
	// none (created: the store is new or was emptied).
	Generation(ctx context.Context) (gen string, created bool, err error)
	// Seed rebuilds entries; an entry seen later than the seed is kept.
	Seed(ctx context.Context, seeds []LivenessSeed) error
	// StartGrace starts the cold-start grace (shared by every replica) and
	// InGrace reports whether it is running.
	StartGrace(ctx context.Context, d time.Duration) error
	InGrace(ctx context.Context) (bool, error)
	// Watched counts the sensors in the due index (the live fleet).
	Watched(ctx context.Context) (int64, error)
}

// LivenessLoad is the volatile part of a heartbeat: what the checkpoint
// writes to Postgres. Every value is already clamped.
type LivenessLoad struct {
	CPUPercent    float64        `json:"cpu,omitempty"`
	MemoryPercent float64        `json:"mem,omitempty"`
	DiskReadMBPS  float64        `json:"dr,omitempty"`
	DiskWriteMBPS float64        `json:"dw,omitempty"`
	NetworkRxMBPS float64        `json:"nr,omitempty"`
	NetworkTxMBPS float64        `json:"nt,omitempty"`
	LoadScore     float64        `json:"ls,omitempty"`
	Load          *LoadReport    `json:"load,omitempty"`
	Outbox        *OutboxStats   `json:"outbox,omitempty"`
	Control       *ControlReport `json:"control,omitempty"`
}

// LivenessCheckpoint is one sensor's liveness and load written to Postgres
// by the batched checkpoint.
type LivenessCheckpoint struct {
	TenantID  *shared.ID
	SensorID  shared.ID
	SeenAt    time.Time
	DueAt     time.Time
	Interval  time.Duration
	KeyUsedAt time.Time
	Load      LivenessLoad
}

// LivenessCheckpointer writes checkpoints in one statement. Implemented by
// postgres.SensorRepository.
type LivenessCheckpointer interface {
	CheckpointLiveness(ctx context.Context, rows []LivenessCheckpoint) (int64, error)
}

// HeartbeatStateDigest is the digest of what a heartbeat stores in Postgres
// besides liveness (seen, due, interval) and load (metrics, the load report,
// outbox, control): versions, addresses, protocol, the capability and local
// policy reports, build, the config digest, the process start (to the
// minute) and whether the sensor reports free slots. When it is unchanged
// and the sensor is online, a heartbeat needs no Postgres write.
func HeartbeatStateDigest(hb HeartbeatUpdate) string {
	type slots struct {
		Total int  `json:"t"`
		Full  bool `json:"f"`
	}
	var sl *slots
	if hb.Load != nil && hb.Load.Capacity != nil {
		sl = &slots{Total: hb.Load.Capacity.SlotsTotal, Full: hb.Load.Capacity.SlotsFree <= 0}
	}
	started := int64(0)
	if up := ClampUptime(hb.UptimeSeconds); up > 0 {
		started = int64(math.Round(float64(time.Now().Unix()-up) / 60))
	}
	ip := ""
	if hb.IPAddress != nil {
		ip = hb.IPAddress.String()
	}
	v := struct {
		Version, Hostname, Region, IP, UA, Binding, Fallback, ConfigDigest string
		Protocol                                                           int
		Started                                                            int64
		Report                                                             *CapabilityReport
		Build                                                              BuildInfo
		LocalPolicy                                                        *LocalPolicyReport
		Slots                                                              *slots
	}{hb.Version, hb.Hostname, hb.Region, ip, hb.UserAgent, hb.Binding, hb.FallbackReason, hb.ConfigReportDigest,
		hb.Protocol, started, hb.Report, hb.Build, hb.LocalPolicy, sl}
	raw, _ := json.Marshal(v)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:12])
}
