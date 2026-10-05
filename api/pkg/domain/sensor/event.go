package sensor

// Sensor activity (docs/architecture/sensors.md "Activity"): what the
// platform observed about a sensor, as events on a timeline. The server
// writes them, never the sensor: each heartbeat is compared with the stored
// row (DiffHeartbeat) and the health transitions add online / offline. Jobs
// come from the commands table and administrator actions from the audit log
// when the timeline is read; they are not copied here.

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// EventType identifies one kind of sensor event.
type EventType string

// Event types written by the server.
const (
	EventOnline               EventType = "online"
	EventOffline              EventType = "offline"
	EventRestarted            EventType = "restarted"
	EventVersionChanged       EventType = "version_changed"
	EventSDKVersionChanged    EventType = "sdk_version_changed"
	EventProtocolChanged      EventType = "protocol_changed"
	EventToolsChanged         EventType = "tools_changed"
	EventCapacityChanged      EventType = "capacity_changed"
	EventContentUpdated       EventType = "content_updated"
	EventContentRefreshFailed EventType = "content_refresh_failed"
	// EventKeyIPChanged: the sensor's key was used from another client
	// address than the last request (RFC-032 Phase 0).
	EventKeyIPChanged EventType = "key_ip_changed"
	// EventIdentityCloned: two live instances use the same key (identity.go).
	EventIdentityCloned EventType = "identity_cloned"
	// EventManifestChanged: a manifest the sensor registered replaced the
	// previous one (RFC-033 §6.12); details carry the diff and both digests.
	EventManifestChanged EventType = "manifest_changed"
	// EventHeartbeatRecovered: a late or stale sensor heartbeated again
	// (RFC-035 §5.6); details carry the gap and the step it reached. A
	// sensor back from offline gets EventOnline instead.
	EventHeartbeatRecovered EventType = "heartbeat_recovered"
	// EventLocalPolicyChanged: the sensor-local policy the sensor reports
	// (RFC-040 §5.7) changed state or digest, or its kill switch moved. An
	// update: identical transitions fold, different ones each get a row.
	EventLocalPolicyChanged EventType = "local_policy_changed"
	// EventJobRefusedByLocalPolicy: the sensor refused a job because its
	// local policy forbids it (RFC-040 detection A11); details carry the
	// command id, rule and reason.
	EventJobRefusedByLocalPolicy EventType = "job_refused_local_policy"
	// EventPairingCompleted: the sensor confirmed the identity a pairing
	// gave it and its key became active (RFC-052); details carry the key
	// fingerprint, the SAS and the source address of the request.
	EventPairingCompleted EventType = "pairing_completed"
)

// ActivityCategory groups timeline items for the filter chips.
type ActivityCategory string

// Timeline categories.
const (
	CategoryPeople  ActivityCategory = "people"  // administrator actions (audit log)
	CategoryStatus  ActivityCategory = "status"  // online, offline, restarted
	CategoryUpdates ActivityCategory = "updates" // version, SDK, protocol, tools, capacity, content
	CategoryJobs    ActivityCategory = "jobs"    // commands claimed and finished
)

// AllCategories lists every category in display order.
func AllCategories() []ActivityCategory {
	return []ActivityCategory{CategoryPeople, CategoryStatus, CategoryUpdates, CategoryJobs}
}

// IsValid reports whether c is a known category.
func (c ActivityCategory) IsValid() bool {
	return slices.Contains(AllCategories(), c)
}

// Category is the timeline category of a server-written event.
func (t EventType) Category() ActivityCategory {
	switch t {
	case EventOnline, EventOffline, EventRestarted, EventKeyIPChanged, EventIdentityCloned, EventHeartbeatRecovered,
		EventPairingCompleted:
		return CategoryStatus
	case EventJobRefusedByLocalPolicy:
		return CategoryJobs
	default:
		return CategoryUpdates
	}
}

// EventTypesIn lists the server-written event types of the given categories.
func EventTypesIn(cats []ActivityCategory) []EventType {
	all := []EventType{EventOnline, EventOffline, EventRestarted, EventVersionChanged, EventSDKVersionChanged,
		EventProtocolChanged, EventToolsChanged, EventCapacityChanged, EventContentUpdated, EventContentRefreshFailed,
		EventKeyIPChanged, EventIdentityCloned, EventManifestChanged, EventHeartbeatRecovered,
		EventLocalPolicyChanged, EventJobRefusedByLocalPolicy, EventPairingCompleted}
	var out []EventType
	for _, t := range all {
		if slices.Contains(cats, t.Category()) {
			out = append(out, t)
		}
	}
	return out
}

// Event is one sensor event.
type Event struct {
	ID       shared.ID
	TenantID shared.ID
	SensorID shared.ID
	Type     EventType
	At       time.Time
	// Summary is a plain-English sentence; clients build their own wording
	// from Type and Details and fall back to it.
	Summary string
	Details map[string]any
	// RepeatCount counts identical events folded into this one (1 = none);
	// LastAt is the latest of them.
	RepeatCount int
	LastAt      *time.Time
}

// NewEvent builds an event for a tenant sensor.
func NewEvent(tenantID, sensorID shared.ID, t EventType, at time.Time, summary string, details map[string]any) Event {
	if details == nil {
		details = map[string]any{}
	}
	return Event{ID: shared.NewID(), TenantID: tenantID, SensorID: sensorID, Type: t, At: at,
		Summary: summary, Details: details, RepeatCount: 1}
}

// EventLimits bound what one sensor can write: identical events (type and
// summary) within CoalesceWindow are folded into one row, and at most
// MaxPerHour rows are written per sensor per hour; the rest are dropped.
type EventLimits struct {
	CoalesceWindow time.Duration
	MaxPerHour     int
}

// DefaultEventLimits are the limits the platform uses.
func DefaultEventLimits() EventLimits {
	return EventLimits{CoalesceWindow: 10 * time.Minute, MaxPerHour: 30}
}

// EventWriteResult says what happened to an event on write.
type EventWriteResult string

// Write outcomes.
const (
	EventInserted  EventWriteResult = "inserted"
	EventCoalesced EventWriteResult = "coalesced"
	EventDropped   EventWriteResult = "dropped"
)

// EventRepository stores sensor events.
type EventRepository interface {
	// Record writes an event under the limits.
	Record(ctx context.Context, e Event, limits EventLimits) (EventWriteResult, error)
	// DeleteOlderThan removes events older than before, at most limit rows.
	DeleteOlderThan(ctx context.Context, before time.Time, limit int) (int64, error)
}

// =============================================================================
// Heartbeat diff
// =============================================================================

// HeartbeatObservation is what one heartbeat says, already sanitized: the
// values about to be written, in the form they are stored.
type HeartbeatObservation struct {
	At       time.Time
	Version  string
	Protocol int
	// StartedAt is the process start derived from the reported uptime; nil
	// when the heartbeat reported none.
	StartedAt *time.Time
	// Report is the sanitized capability report; nil when none was carried.
	Report *CapabilityReport
	// Build is the resolved build information; empty when unknown.
	Build BuildInfo
}

// restartTolerance absorbs the jitter of a start time derived from
// NOW() - uptime (request latency, whole-second uptimes).
const restartTolerance = 15 * time.Second

// DiffHeartbeat returns the events that a heartbeat represents for the
// sensor as it is stored (prev): a restart, a new version, SDK or protocol,
// changed tools, capacity or content. A part the heartbeat does not carry,
// or that the sensor never reported before, produces nothing: the first
// report is not a change.
func DiffHeartbeat(prev *Sensor, hb HeartbeatObservation) []Event {
	if prev == nil || prev.TenantID == nil {
		return nil
	}
	d := differ{prev: prev, hb: hb}
	d.restart()
	d.version()
	d.sdk()
	d.protocol()
	if hb.Report != nil {
		d.tools()
		d.capacity()
		d.content()
	}
	return d.out
}

type differ struct {
	prev *Sensor
	hb   HeartbeatObservation
	out  []Event
}

func (d *differ) add(t EventType, summary string, details map[string]any) {
	d.out = append(d.out, NewEvent(*d.prev.TenantID, d.prev.ID, t, d.hb.At, summary, details))
}

func (d *differ) restart() {
	prevStart, newStart := d.prev.StartedAt, d.hb.StartedAt
	if prevStart == nil || newStart == nil || !newStart.After(prevStart.Add(restartTolerance)) {
		return
	}
	details := map[string]any{
		"started_at":          newStart.UTC().Format(time.RFC3339),
		"previous_started_at": prevStart.UTC().Format(time.RFC3339),
	}
	summary := "Sensor process restarted"
	if last := d.prev.LastSeenAt; last != nil && newStart.After(*last) {
		down := newStart.Sub(*last)
		details["downtime_seconds"] = int64(down / time.Second)
		summary = fmt.Sprintf("Sensor process restarted (down %s)", humanDuration(down))
	}
	d.add(EventRestarted, summary, details)
}

func (d *differ) version() {
	from, to := NormalizeVersion(d.prev.Version), NormalizeVersion(d.hb.Version)
	if from == "" || to == "" || from == to {
		return
	}
	dir := VersionDirection(from, to)
	d.add(EventVersionChanged, fmt.Sprintf("Sensor version %s → %s (%s)", from, to, dir),
		map[string]any{"from": from, "to": to, "direction": dir})
}

func (d *differ) sdk() {
	from, to := d.prev.Build.SDKVersion, d.hb.Build.SDKVersion
	if from == "" || to == "" || from == to {
		return
	}
	name := d.hb.Build.SDKName
	if name == "" {
		name = d.prev.Build.SDKName
	}
	dir := VersionDirection(from, to)
	label := name
	if label == "" {
		label = "SDK"
	}
	d.add(EventSDKVersionChanged, fmt.Sprintf("%s %s → %s (%s)", label, from, to, dir),
		map[string]any{"name": name, "from": from, "to": to, "direction": dir})
}

func (d *differ) protocol() {
	if d.prev.Protocol == nil || d.hb.Protocol <= 0 || d.prev.Protocol.Version <= 0 ||
		d.prev.Protocol.Version == d.hb.Protocol {
		return
	}
	from, to := d.prev.Protocol.Version, d.hb.Protocol
	d.add(EventProtocolChanged, fmt.Sprintf("Protocol v%d → v%d", from, to),
		map[string]any{"from": from, "to": to})
}

func (d *differ) tools() {
	if d.prev.Reported.Tools == nil || d.hb.Report.Tools == nil {
		return
	}
	before, after := installedTools(d.prev.Reported.Tools), installedTools(d.hb.Report.Tools)
	var added, removed, updated []map[string]any
	for _, name := range sortedKeys(after) {
		v, ok := before[name]
		switch {
		case !ok:
			added = append(added, toolRef(name, after[name]))
		case v != after[name] && v != "" && after[name] != "":
			updated = append(updated, map[string]any{"name": name, "from": v, "to": after[name]})
		}
	}
	for _, name := range sortedKeys(before) {
		if _, ok := after[name]; !ok {
			removed = append(removed, toolRef(name, before[name]))
		}
	}
	if len(added)+len(removed)+len(updated) == 0 {
		return
	}
	details := map[string]any{"added": emptyIfNil(added), "removed": emptyIfNil(removed), "updated": emptyIfNil(updated)}
	d.add(EventToolsChanged, fmt.Sprintf("Tools changed: %d added, %d removed, %d updated",
		len(added), len(removed), len(updated)), details)
}

func (d *differ) capacity() {
	if d.hb.Report.MaxConcurrentJobs <= 0 {
		return
	}
	next := *d.prev
	next.Reported.MaxConcurrentJobs = d.hb.Report.MaxConcurrentJobs
	from, to := d.prev.EffectiveMaxConcurrentJobs(), next.EffectiveMaxConcurrentJobs()
	if from == to {
		return
	}
	d.add(EventCapacityChanged, fmt.Sprintf("Job capacity %d → %d", from, to),
		map[string]any{"from": from, "to": to})
}

func (d *differ) content() {
	if d.prev.Reported.Tools == nil || d.hb.Report.Tools == nil {
		return
	}
	type key struct{ tool, name string }
	before := map[key]ReportedContent{}
	for _, t := range d.prev.Reported.Tools {
		for _, c := range t.Content {
			before[key{t.Name, c.Name}] = normalizeContent(c)
		}
	}
	var updated, failed []map[string]any
	installed := 0
	for _, t := range d.hb.Report.Tools {
		for _, c := range t.Content {
			old, ok := before[key{t.Name, c.Name}]
			if !ok {
				continue
			}
			c = normalizeContent(c)
			// A first install (nothing before) is an update too: it is how a
			// failure or a fresh container recovers on the timeline.
			if c.Version != "" && old.Version != c.Version {
				if old.Version == "" {
					installed++
				}
				updated = append(updated, map[string]any{"tool": t.Name, "name": c.Name, "from": old.Version, "to": c.Version})
			}
			if c.Error != "" && c.Error != old.Error {
				failed = append(failed, map[string]any{"tool": t.Name, "name": c.Name, "error": c.Error})
			}
		}
	}
	if len(updated) > 0 {
		prefix := "Content updated"
		if installed == len(updated) {
			prefix = "Content installed"
		}
		d.add(EventContentUpdated, contentSummary(prefix, updated), map[string]any{"items": updated})
	}
	if len(failed) > 0 {
		d.add(EventContentRefreshFailed, contentSummary("Content refresh failed", failed), map[string]any{"items": failed})
	}
}

func contentSummary(prefix string, items []map[string]any) string {
	names := make([]string, 0, len(items))
	for _, it := range items {
		names = append(names, fmt.Sprint(it["name"]))
	}
	sort.Strings(names)
	s := prefix + ": "
	for i, n := range names {
		if i > 0 {
			s += ", "
		}
		s += n
	}
	return s
}

func installedTools(tools []ReportedTool) map[string]string {
	out := make(map[string]string, len(tools))
	for _, t := range tools {
		if t.Installed {
			out[t.Name] = t.Version
		}
	}
	return out
}

func toolRef(name, version string) map[string]any {
	m := map[string]any{"name": name}
	if version != "" {
		m["version"] = version
	}
	return m
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func emptyIfNil(in []map[string]any) []map[string]any {
	if in == nil {
		return []map[string]any{}
	}
	return in
}

// OnlineEvent is the event for a sensor that came back online at at.
// offlineSince is when it was marked offline (nil when unknown or never).
func OnlineEvent(s *Sensor, at time.Time) (Event, bool) {
	if s == nil || s.TenantID == nil {
		return Event{}, false
	}
	details := map[string]any{}
	summary := "Came online"
	if s.LastSeenAt == nil {
		summary = "Connected for the first time"
	} else if s.Health == SensorHealthOffline && at.After(*s.LastSeenAt) {
		gap := at.Sub(*s.LastSeenAt)
		details["offline_seconds"] = int64(gap / time.Second)
		summary = fmt.Sprintf("Came back online after %s", humanDuration(gap))
	}
	return NewEvent(*s.TenantID, s.ID, EventOnline, at, summary, details), true
}

// RecoveredEvent is the event for a sensor whose heartbeat arrives at at
// after its own deadline had passed far enough to make it late, stale or
// offline (RFC-035 §5.6), judged on the heartbeat deadline alone: polls and
// other requests do not count, and neither does whether the health
// controller already ticked. false when the heartbeat is on time or the
// sensor has no stored deadline. Status events coalesce on type, so a sensor
// that keeps slipping folds into one row with a repeat count.
func RecoveredEvent(s *Sensor, at time.Time) (Event, bool) {
	if s == nil || s.TenantID == nil || s.HeartbeatDueAt == nil {
		return Event{}, false
	}
	pos := Ladder(at, HeartbeatDeadline{DueAt: s.HeartbeatDueAt, Interval: s.HeartbeatInterval})
	if pos.State == SensorHealthOnline {
		return Event{}, false
	}
	details := map[string]any{"was": string(pos.State), "interval_seconds": int64(pos.Interval / time.Second)}
	summary := fmt.Sprintf("Heartbeats back after being %s", pos.State)
	if prev := s.PreviousHeartbeatAt(); prev != nil && at.After(*prev) {
		gap := at.Sub(*prev)
		details["gap_seconds"] = int64(gap / time.Second)
		summary = fmt.Sprintf("Heartbeats back after a %s gap (was %s)", humanDuration(gap), pos.State)
	}
	return NewEvent(*s.TenantID, s.ID, EventHeartbeatRecovered, at, summary, details), true
}

// PreviousHeartbeatAt is when the sensor's last heartbeat arrived, from its
// stored deadline (due = heartbeat + interval); nil without one. Unlike
// LastSeenAt it is not moved by polls or other requests.
func (a *Sensor) PreviousHeartbeatAt() *time.Time {
	if a == nil || a.HeartbeatDueAt == nil || a.HeartbeatInterval <= 0 {
		return nil
	}
	t := a.HeartbeatDueAt.Add(-a.HeartbeatInterval)
	return &t
}

// OfflineEvent is the event for a sensor the health checker marked offline.
func OfflineEvent(s *Sensor, at time.Time) (Event, bool) {
	if s == nil || s.TenantID == nil {
		return Event{}, false
	}
	details := map[string]any{}
	if s.LastSeenAt != nil {
		details["last_seen_at"] = s.LastSeenAt.UTC().Format(time.RFC3339)
	}
	return NewEvent(*s.TenantID, s.ID, EventOffline, at, "Went offline (no heartbeat)", details), true
}

// coalescesOnType reports whether identical-type events fold together
// regardless of their summary. Status events do (a flapping or crash-looping
// sensor gives one row per state, its summary carrying a varying downtime);
// update events fold only when the summary is the same (the same change).
func (t EventType) coalescesOnType() bool {
	return t.Category() == CategoryStatus
}

// CoalesceSummary is the summary two events must share to fold together; ""
// when the type alone decides.
func (e Event) CoalesceSummary() string {
	if e.Type.coalescesOnType() {
		return ""
	}
	return e.Summary
}
