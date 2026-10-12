package sensor

// The sensor config report (research/26; pkg/domain/sensor/config_report.go):
// ingest (PUT /api/v2/sensor/config-report) and the management read
// (GET /api/v1/sensors/{id}/config-report), explained from the platform
// catalog (config_check_catalog.go).

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"time"

	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Errors of RegisterConfigReport besides the parse errors of
// sensordom.SanitizeConfigReport.
var (
	// ErrConfigReportUnavailable: config reports are not stored here.
	ErrConfigReportUnavailable = errors.New("sensor config report store unavailable")
	// ErrConfigReportSensorInactive: the sensor was disabled or revoked,
	// or has no tenant.
	ErrConfigReportSensorInactive = fmt.Errorf("%w: sensor is not active", shared.ErrForbidden)
)

func (s *SensorService) configReportStore() (sensordom.ConfigReportStore, bool) {
	if s == nil {
		return nil, false
	}
	store, ok := s.repo.(sensordom.ConfigReportStore)
	return store, ok
}

// SupportsConfigReports reports whether config reports are stored (the v2
// hello lists the config_report feature only then).
func (s *SensorService) SupportsConfigReports() bool {
	_, ok := s.configReportStore()
	return ok
}

// ConfigReportResult answers a stored config report.
type ConfigReportResult struct {
	// Digest is the platform's digest of the sanitized report; the sensor
	// echoes it as its heartbeat's config_report.digest.
	Digest string
	// Changed is false when the report was already the stored one.
	Changed bool
	Ignored []sensordom.ConfigIgnored
}

// RegisterConfigReport sanitizes the report a sensor sent (raw, the request
// body), stores it as the sensor's latest, and answers its digest and what
// was dropped. The health is the platform's rollup of the sanitized checks.
func (s *SensorService) RegisterConfigReport(ctx context.Context, a *sensordom.Sensor, raw []byte) (*ConfigReportResult, error) {
	store, ok := s.configReportStore()
	if !ok {
		return nil, ErrConfigReportUnavailable
	}
	if a.TenantID == nil {
		return nil, ErrConfigReportSensorInactive
	}
	rep, ignored, err := sensordom.SanitizeConfigReport(raw)
	if err != nil {
		return nil, err
	}
	digest, err := rep.Digest()
	if err != nil {
		return nil, fmt.Errorf("failed to digest sensor config report: %w", err)
	}
	health := sensordom.ConfigHealthOf(rep.Checks)
	saved, changed, err := store.SaveConfigReport(ctx, *a.TenantID, a.ID, rep, digest, health, s.now())
	if err != nil {
		return nil, fmt.Errorf("failed to store sensor config report: %w", err)
	}
	if !saved {
		return nil, ErrConfigReportSensorInactive
	}
	if changed {
		s.logger.Info("sensor config report stored", "sensor_id", a.ID.String(), "digest", digest,
			"health", health, "checks", len(rep.Checks), "ignored", len(ignored))
	}
	if ignored == nil {
		ignored = []sensordom.ConfigIgnored{}
	}
	return &ConfigReportResult{Digest: digest, Changed: changed, Ignored: ignored}, nil
}

// Config report view states.
const (
	ConfigReportStateReported = "reported"
	ConfigReportStateDerived  = "derived"
	ConfigReportStateNone     = "none"
)

// ConfigReportView is a sensor's setup checklist as the console shows it.
type ConfigReportView struct {
	State       string
	Stale       bool
	Health      string
	ObservedAt  *time.Time
	ReceivedAt  *time.Time
	Truncated   bool
	RuntimeKind string
	DerivedNote string
	Counts      sensordom.ConfigCounts
	Checks      []ConfigCheckView
	Settings    []sensordom.ConfigSetting
}

// ConfigCheckView is one check with the catalog's explanation.
type ConfigCheckView struct {
	Check       sensordom.ConfigCheck
	Explanation CheckExplanation
}

// ConfigReport returns the setup checklist of a tenant's sensor: its
// stored report, a checklist derived from its heartbeat when it sends
// none, or nothing when it never connected. shared.ErrNotFound when the
// sensor is not the tenant's.
func (s *SensorService) ConfigReport(ctx context.Context, tenantID, sensorID string) (*ConfigReportView, error) {
	a, err := s.GetSensor(ctx, tenantID, sensorID)
	if err != nil {
		return nil, err
	}
	view := &ConfigReportView{State: ConfigReportStateNone, Health: sensordom.ConfigHealthUnknown,
		RuntimeKind: "unknown", Checks: []ConfigCheckView{}, Settings: []sensordom.ConfigSetting{}}

	var checks []sensordom.ConfigCheck
	if store, ok := s.configReportStore(); ok && a.ConfigReportDigest != "" && a.TenantID != nil {
		stored, err := store.GetConfigReport(ctx, *a.TenantID, a.ID)
		switch {
		case err == nil:
			view.State = ConfigReportStateReported
			view.Stale = a.ConfigReportStale()
			view.Health = stored.Health
			if view.Stale {
				view.Health = sensordom.ConfigHealthUnknown
			}
			if t, err := time.Parse(time.RFC3339, stored.Report.ObservedAt); err == nil {
				view.ObservedAt = &t
			}
			received := stored.ReceivedAt
			view.ReceivedAt = &received
			view.Truncated = stored.Report.Truncated
			view.RuntimeKind = stored.Report.Runtime.Kind
			checks = stored.Report.Checks
			if stored.Report.Settings != nil {
				view.Settings = stored.Report.Settings
			}
		case !errors.Is(err, shared.ErrNotFound):
			return nil, err
		}
	}
	if view.State == ConfigReportStateNone && a.LastSeenAt != nil {
		view.State = ConfigReportStateDerived
		view.DerivedNote = sensordom.DerivedConfigNote
		checks = a.DerivedConfigChecks()
		view.Health = sensordom.ConfigHealthOf(checks)
		view.ReceivedAt = a.LastSeenAt
	}

	view.Counts = sensordom.CountChecks(checks)
	for _, c := range checks {
		view.Checks = append(view.Checks, ConfigCheckView{Check: c, Explanation: ExplainCheck(c)})
	}
	sortConfigChecks(view.Checks)
	return view, nil
}

var configStatusOrder = []string{sensordom.CheckFail, sensordom.CheckError, sensordom.CheckWarn, sensordom.CheckSkip, sensordom.CheckPass}

// sortConfigChecks orders checks fail, error, warn, skip, pass; then by
// group (ConfigCheckGroups order); then by id.
func sortConfigChecks(checks []ConfigCheckView) {
	rank := func(set []string, v string) int {
		if i := slices.Index(set, v); i >= 0 {
			return i
		}
		return len(set)
	}
	sort.SliceStable(checks, func(i, j int) bool {
		a, b := checks[i], checks[j]
		if ra, rb := rank(configStatusOrder, a.Check.Status), rank(configStatusOrder, b.Check.Status); ra != rb {
			return ra < rb
		}
		if ga, gb := rank(ConfigCheckGroups, a.Explanation.Group), rank(ConfigCheckGroups, b.Explanation.Group); ga != gb {
			return ga < gb
		}
		return a.Check.ID < b.Check.ID
	})
}
