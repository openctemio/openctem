package sensor

// The sensor manifest (docs/rfcs/RFC-033-sensor-manifest.md): registration
// (PUT /api/v2/sensor/manifest), manifests derived from the heartbeat of
// sensors that send none, and the management reads.

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Errors of RegisterManifest besides the parse errors of
// sensordom.ParseManifest.
var (
	// ErrManifestUnavailable: manifests are not stored here, or the tool
	// catalog could not be read; the sensor retries later.
	ErrManifestUnavailable = errors.New("sensor manifest store unavailable")
	// ErrManifestSensorInactive: the sensor was disabled or revoked.
	ErrManifestSensorInactive = fmt.Errorf("%w: sensor is not active", shared.ErrForbidden)
	// ErrManifestNotRegistered: the sensor has no current manifest.
	ErrManifestNotRegistered = fmt.Errorf("%w: no manifest registered", shared.ErrNotFound)
)

// SetSlimHeartbeat turns slim heartbeats on or off (RFC-033 §6.12, owner
// decision O3; SENSOR_SLIM_HEARTBEAT). On by default.
func (s *SensorService) SetSlimHeartbeat(on bool) {
	s.slimHeartbeatOff = !on
}

// SlimHeartbeat reports whether sensors may leave their inventory out of
// heartbeats once their manifest is acknowledged.
func (s *SensorService) SlimHeartbeat() bool {
	return s != nil && !s.slimHeartbeatOff
}

// ManifestResult is the answer to a registered manifest.
type ManifestResult struct {
	// Digest is the digest the platform stored; the sensor echoes it as
	// its heartbeat's manifest_digest.
	Digest string
	// Changed is false when the manifest was already the current one.
	Changed bool
	// AcceptedTools are the tools kept; AcceptedCapabilities the flat
	// capability list dispatch reads.
	AcceptedTools        []string
	AcceptedCapabilities []string
	// Ignored is what the sanitizing dropped.
	Ignored []sensordom.ManifestIgnored
	// Policy is what the platform lets the sensor run now (owner decision
	// O2): the SDK refuses commands for tools outside it.
	Policy sensordom.ManifestPolicy
	// OmitInventory: the sensor may leave its tool inventory out of
	// heartbeats while it echoes Digest (owner decision O3).
	OmitInventory bool
}

// ManifestState answers GET /api/v2/sensor/manifest: the sensor's current
// manifest digest and its policy as it stands now (the SDK re-reads it when
// config_version changes). ErrManifestNotRegistered when it has none.
func (s *SensorService) ManifestState(a *sensordom.Sensor) (*ManifestResult, error) {
	if a.ManifestDigest == "" {
		return nil, ErrManifestNotRegistered
	}
	return &ManifestResult{Digest: a.ManifestDigest, Policy: a.ManifestPolicy(), OmitInventory: s.SlimHeartbeat()}, nil
}

func (s *SensorService) manifestStore() (sensordom.ManifestStore, bool) {
	store, ok := s.repo.(sensordom.ManifestStore)
	return store, ok
}

// SupportsManifests reports whether manifests are stored (the v2 hello
// lists the manifest feature only then).
func (s *SensorService) SupportsManifests() bool {
	if s == nil {
		return false
	}
	_, ok := s.manifestStore()
	return ok
}

// RegisterManifest stores the manifest a sensor sent (raw, the request body)
// and answers what was kept. An unchanged manifest only confirms the stored
// version. A new one becomes current: its projection replaces the sensor's
// reported tools, capabilities, ceiling and platform, and what changed is
// written to the activity timeline.
func (s *SensorService) RegisterManifest(ctx context.Context, a *sensordom.Sensor, raw []byte) (*ManifestResult, error) {
	store, ok := s.manifestStore()
	if !ok {
		return nil, ErrManifestUnavailable
	}
	m, digest, ignoredMembers, err := sensordom.ParseManifest(raw)
	if err != nil {
		return nil, err
	}
	in := m.CapabilityInput()
	report := s.sanitizeReport(ctx, a, &in)
	if report == nil {
		return nil, ErrManifestUnavailable
	}
	now := s.now()
	clean, ignored := m.Sanitized(*report, now)
	ignored = append(ignoredMembers, ignored...)
	if len(ignored) > sensordom.MaxManifestIgnored {
		ignored = ignored[:sensordom.MaxManifestIgnored]
	}
	// The policy as it will stand with this manifest's projection.
	projected := *a
	projected.Reported = *report
	res := &ManifestResult{
		Digest:               digest,
		AcceptedTools:        clean.AcceptedToolNames(),
		AcceptedCapabilities: slices.Clone(report.Capabilities),
		Ignored:              ignored,
		Policy:               projected.ManifestPolicy(),
		OmitInventory:        s.SlimHeartbeat(),
	}

	s.storeManifestLocalPolicy(ctx, a, clean.LocalPolicy, now)

	if digest == a.ManifestDigest {
		if err := store.TouchManifest(ctx, a.TenantID, a.ID, digest, now); err != nil {
			s.logger.Warn("failed to confirm sensor manifest", "sensor_id", a.ID.String(), "error", err)
		}
		return res, nil
	}

	// The version it replaces, for the manifest_changed event.
	var prev *sensordom.ManifestVersion
	if a.ManifestDigest != "" && a.TenantID != nil && s.events != nil {
		if p, err := store.CurrentManifest(ctx, a.TenantID, a.ID); err == nil {
			prev = p
		}
	}

	saved, err := store.SaveManifest(ctx, sensordom.ManifestVersion{
		SensorID: a.ID, TenantID: a.TenantID, Digest: digest,
		Source: sensordom.ManifestSourceSensor, Manifest: clean, Ignored: ignored,
	}, report, now)
	if err != nil {
		return nil, fmt.Errorf("failed to store sensor manifest: %w", err)
	}
	if !saved {
		return nil, ErrManifestSensorInactive
	}
	res.Changed = true
	s.logger.Info("sensor manifest registered", "sensor_id", a.ID.String(), "digest", digest,
		"tools", len(clean.Tools), "ignored", len(ignored))

	if a.TenantID != nil && s.events != nil {
		s.recordEvents(ctx, withManifestDigests(s.manifestEvents(a, prev, clean, report, now), a.ManifestDigest, digest))
	}
	return res, nil
}

// manifestEvents are the timeline entries of a newly registered manifest
// (RFC-033 §6.12): one manifest_changed with the diff against the version it
// replaces, plus the content events of the projection (content versions
// have their own events). A first manifest is not a change.
func (s *SensorService) manifestEvents(a *sensordom.Sensor, prev *sensordom.ManifestVersion, next sensordom.Manifest,
	report *sensordom.CapabilityReport, now time.Time) []sensordom.Event {
	var events []sensordom.Event
	if prev != nil {
		if d := sensordom.DiffManifests(prev.Manifest, next); !d.IsEmpty() {
			events = append(events, sensordom.NewEvent(*a.TenantID, a.ID, sensordom.EventManifestChanged, now, d.Summary(),
				map[string]any{"diff": d, "previous_source": prev.Source}))
		}
	}
	for _, e := range sensordom.DiffHeartbeat(a, sensordom.HeartbeatObservation{At: now, Report: report}) {
		if e.Type == sensordom.EventContentUpdated || e.Type == sensordom.EventContentRefreshFailed {
			events = append(events, e)
		}
	}
	return events
}

// recordDerivedManifest stores the manifest a heartbeat implies for a
// sensor that sends none (RFC-033 §6.6), when it differs from the current
// one. The heartbeat already wrote the report and its events; this adds the
// version history. Best-effort: a failure is logged and retried by the next
// heartbeat (the digest still differs).
func (s *SensorService) recordDerivedManifest(ctx context.Context, a *sensordom.Sensor, report *sensordom.CapabilityReport,
	build sensordom.BuildInfo, version string, now time.Time) {
	store, ok := s.manifestStore()
	if !ok || report == nil || report.Tools == nil {
		return
	}
	m := sensordom.ManifestFromReport(*report, build, version)
	digest, err := m.Digest()
	if err != nil || digest == a.ManifestDigest {
		return
	}
	if _, err := store.SaveManifest(ctx, sensordom.ManifestVersion{
		SensorID: a.ID, TenantID: a.TenantID, Digest: digest,
		Source: sensordom.ManifestSourceHeartbeat, Manifest: m,
	}, nil, now); err != nil {
		s.logger.Warn("failed to store derived sensor manifest", "sensor_id", a.ID.String(), "error", err)
	}
}

// withManifestDigests adds the previous and the new manifest digest to
// each event's details.
func withManifestDigests(events []sensordom.Event, from, to string) []sensordom.Event {
	for i := range events {
		if events[i].Details == nil {
			events[i].Details = map[string]any{}
		}
		events[i].Details["manifest_digest"] = to
		if from != "" {
			events[i].Details["previous_manifest_digest"] = from
		}
	}
	return events
}

// CurrentManifest returns the current manifest of a tenant's sensor;
// shared.ErrNotFound when the sensor is not the tenant's or has none.
func (s *SensorService) CurrentManifest(ctx context.Context, tenantID, sensorID string) (*sensordom.ManifestVersion, error) {
	a, store, err := s.manifestSensor(ctx, tenantID, sensorID)
	if err != nil {
		return nil, err
	}
	return store.CurrentManifest(ctx, a.TenantID, a.ID)
}

// ListManifests returns the manifest versions of a tenant's sensor, most
// recently current first.
func (s *SensorService) ListManifests(ctx context.Context, tenantID, sensorID string, limit int) ([]sensordom.ManifestVersion, error) {
	a, store, err := s.manifestSensor(ctx, tenantID, sensorID)
	if err != nil {
		return nil, err
	}
	return store.ListManifests(ctx, a.TenantID, a.ID, limit)
}

func (s *SensorService) manifestSensor(ctx context.Context, tenantID, sensorID string) (*sensordom.Sensor, sensordom.ManifestStore, error) {
	store, ok := s.manifestStore()
	if !ok {
		return nil, nil, shared.ErrNotFound
	}
	a, err := s.GetSensor(ctx, tenantID, sensorID)
	if err != nil {
		return nil, nil, err
	}
	return a, store, nil
}

// withSlimContent turns a slim heartbeat's content block (RFC-033 §6.12)
// into a report: the stored tools, each with the content the heartbeat sent
// for it (a tool it sent none for keeps its stored content). A heartbeat
// that carries tools, or no content, or a sensor with no stored tools, is
// returned as it is.
func withSlimContent(a *sensordom.Sensor, in *sensordom.CapabilityReportInput, content []sensordom.ReportedContent) *sensordom.CapabilityReportInput {
	if content == nil || a.Reported.Tools == nil || (in != nil && in.Tools != nil) {
		return in
	}
	byTool := map[string][]sensordom.ReportedContent{}
	for i, c := range content {
		if i >= sensordom.MaxReportedTools*sensordom.MaxReportedContentPerTool {
			break
		}
		c.Tool = strings.ToLower(strings.TrimSpace(c.Tool))
		byTool[c.Tool] = append(byTool[c.Tool], c)
	}
	out := sensordom.CapabilityReportInput{}
	if in != nil {
		out = *in
	}
	out.Tools = make([]sensordom.ReportedTool, 0, len(a.Reported.Tools))
	for _, t := range a.Reported.Tools {
		if c, ok := byTool[t.Name]; ok {
			t.Content = c
		}
		out.Tools = append(out.Tools, t)
	}
	return &out
}
