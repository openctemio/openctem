package scanpolicy

// Anomaly signals of shared sensor use (docs/rfcs/RFC-100-shared-sensors.md
// §9): shared sensors send packets from the operator's addresses, so the
// operator wants to hear when an organization starts using them in a way an
// abuser would. Three signals, counted per organization per UTC day:
//
//   - distinct registrable domains sent to shared sensors (someone pointing
//     the pool at many third parties);
//   - failed shared jobs (targets that refuse or drop the scanners);
//   - deny-list hits (targets the platform never scans, on any sensor).
//
// When a count first reaches its threshold that day, the platform raises one
// alert: a metric (labeled by signal only), a warning log line, a high
// severity admin audit row naming the organization, and an email to every
// administrator. The thresholds are an instance setting (console, super
// admin, step-up, reason, audit); 0 turns a signal off.
//
// Aggregate only: the counters keep no target. The distinct-domain count is a
// probabilistic cardinality estimate (the store keeps no member), the others
// are plain counts, and every key carries the organization and the day and
// expires after two days. The alert names the organization, the signal, the
// count and the threshold, never a target.
//
// Threat model: the signals are detective, not preventive. The preventive
// controls (rollout gate, access policy, proof, deny list, scope gate,
// limits, the per-organization kill switch) never read them, so a failed or
// missing counter store never blocks a scan; it is logged and the signal is
// lost for that event. An organization cannot read or reset its counters (no
// tenant route); the thresholds are changed only from the console.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"

	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// AnomalyThresholdsSettingKey is the platform_settings key of the
// thresholds.
const AnomalyThresholdsSettingKey = "shared_sensor_anomaly_thresholds"

// Admin audit actions.
const (
	ActionAnomalyThresholdsChanged = "platform.shared_sensor_anomaly_thresholds_changed"
	ActionSharedSensorAnomaly      = "organization.shared_sensor_anomaly"
)

// Anomaly signals (metric label values).
const (
	SignalDistinctDomains = "distinct_domains"
	SignalFailures        = "failures"
	SignalDenyListHits    = "deny_list_hits"
)

// MaxAnomalyThreshold bounds a threshold (a larger value is a typo).
const MaxAnomalyThreshold = 1_000_000

// anomalyTTL keeps a day's counters a little past the day.
const anomalyTTL = 48 * time.Hour

// anomalyTimeout bounds one observation: signals never hold up a request.
const anomalyTimeout = 2 * time.Second

// AnomalyThresholds are the per-organization daily thresholds. 0 turns a
// signal off.
type AnomalyThresholds struct {
	DistinctDomainsPerDay int `json:"distinct_domains_per_day"`
	FailuresPerDay        int `json:"failures_per_day"`
	DenyListHitsPerDay    int `json:"deny_list_hits_per_day"`
}

// DefaultAnomalyThresholds are conservative: an organization scanning its
// own estate stays far below them.
func DefaultAnomalyThresholds() AnomalyThresholds {
	return AnomalyThresholds{DistinctDomainsPerDay: 25, FailuresPerDay: 50, DenyListHitsPerDay: 5}
}

// Validate refuses a negative or absurd threshold.
func (t AnomalyThresholds) Validate() error {
	for _, v := range []int{t.DistinctDomainsPerDay, t.FailuresPerDay, t.DenyListHitsPerDay} {
		if v < 0 || v > MaxAnomalyThreshold {
			return fmt.Errorf("%w: each threshold is between 0 (off) and %d", shared.ErrValidation, MaxAnomalyThreshold)
		}
	}
	return nil
}

func (t AnomalyThresholds) of(signal string) int {
	switch signal {
	case SignalDistinctDomains:
		return t.DistinctDomainsPerDay
	case SignalFailures:
		return t.FailuresPerDay
	case SignalDenyListHits:
		return t.DenyListHitsPerDay
	}
	return 0
}

// AnomalyThresholdsStore persists the thresholds (platform_settings). Get
// returns ErrNotFound when nothing is stored.
type AnomalyThresholdsStore interface {
	GetAnomalyThresholds(ctx context.Context) (AnomalyThresholds, int, error)
	SetAnomalyThresholds(ctx context.Context, t AnomalyThresholds, expectedVersion int, by string, at time.Time) (int, error)
}

// AnomalyCounter keeps the daily counters across API replicas (Redis). Every
// key it is given carries the organization and the day; it sets ttl on each.
type AnomalyCounter interface {
	// AddDistinct adds members to a cardinality estimate and returns the
	// estimate. The store keeps no member.
	AddDistinct(ctx context.Context, key string, members []string, ttl time.Duration) (int64, error)
	// Incr adds n to a count and returns it.
	Incr(ctx context.Context, key string, n int64, ttl time.Duration) (int64, error)
	// Once reports true the first time it is called for key.
	Once(ctx context.Context, key string, ttl time.Duration) (bool, error)
}

// AnomalyMetrics records the signals as aggregate metrics (labels: signal
// only, never an organization).
type AnomalyMetrics interface {
	ObserveSharedSensorSignal(signal string, n int)
	ObserveSharedSensorAnomaly(signal string)
}

// SetAnomalyCounter wires the counter store and the metrics. Without a store
// the signals are off.
func (s *Service) SetAnomalyCounter(c AnomalyCounter, m AnomalyMetrics) {
	s.counter, s.metrics = c, m
}

func (s *Service) thresholdsStore() (AnomalyThresholdsStore, error) {
	st, ok := s.repo.(AnomalyThresholdsStore)
	if !ok || st == nil {
		return nil, errors.New("the anomaly thresholds store is not wired")
	}
	return st, nil
}

// AnomalyThresholdsSetting returns the thresholds and their version (0:
// nothing stored, the defaults apply).
func (s *Service) AnomalyThresholdsSetting(ctx context.Context) (AnomalyThresholds, int, error) {
	st, err := s.thresholdsStore()
	if err != nil {
		return AnomalyThresholds{}, 0, err
	}
	t, ver, err := st.GetAnomalyThresholds(ctx)
	if errors.Is(err, ErrNotFound) {
		return DefaultAnomalyThresholds(), 0, nil
	}
	if err != nil {
		return AnomalyThresholds{}, 0, err
	}
	return t, ver, nil
}

// thresholds is AnomalyThresholdsSetting cached briefly; an unreadable
// setting falls back to the defaults (the signals stay on).
func (s *Service) thresholds(ctx context.Context) AnomalyThresholds {
	s.mu.Lock()
	if s.thresholdsCached != nil && time.Since(s.thresholdsAt) < cacheTTL {
		t := *s.thresholdsCached
		s.mu.Unlock()
		return t
	}
	s.mu.Unlock()
	t, _, err := s.AnomalyThresholdsSetting(ctx)
	if err != nil {
		s.log.Warn("shared sensor anomaly thresholds unreadable; using the defaults", "error", err)
		t = DefaultAnomalyThresholds()
	}
	s.mu.Lock()
	s.thresholdsCached, s.thresholdsAt = &t, time.Now()
	s.mu.Unlock()
	return t
}

// UpdateAnomalyThresholds changes the thresholds. The caller checked
// super_admin and a fresh authenticator code.
func (s *Service) UpdateAnomalyThresholds(ctx context.Context, t AnomalyThresholds, expectedVersion int, c Change) (int, error) {
	if err := c.check(); err != nil {
		return 0, err
	}
	if err := t.Validate(); err != nil {
		return 0, err
	}
	st, err := s.thresholdsStore()
	if err != nil {
		return 0, err
	}
	prev, _, err := s.AnomalyThresholdsSetting(ctx)
	if err != nil {
		return 0, err
	}
	v, err := st.SetAnomalyThresholds(ctx, t, expectedVersion, c.Actor.ID().String(), time.Now().UTC())
	if err != nil {
		return 0, err
	}
	s.mu.Lock()
	s.thresholdsCached, s.thresholdsAt = &t, time.Now()
	s.mu.Unlock()
	from, to := thresholdsText(prev), thresholdsText(t)
	s.recordKey(ctx, c, ActionAnomalyThresholdsChanged, AnomalyThresholdsSettingKey, from, to)
	s.mailOthers(ctx, c, "[Scans] Shared sensor anomaly thresholds changed",
		fmt.Sprintf("%s changed the shared sensor anomaly thresholds from %s to %s. Reason: %s",
			c.Actor.Email(), from, to, strings.TrimSpace(c.Reason)))
	return v, nil
}

func thresholdsText(t AnomalyThresholds) string {
	return fmt.Sprintf("domains/day %d, failures/day %d, deny-list hits/day %d",
		t.DistinctDomainsPerDay, t.FailuresPerDay, t.DenyListHitsPerDay)
}

// ObserveSharedTargets counts the registrable domains of a job queued for
// shared sensors. Addresses and ranges are not domains and are not counted.
func (s *Service) ObserveSharedTargets(ctx context.Context, tenantID shared.ID, targets []string) {
	domains := registrableDomains(targets)
	if len(domains) == 0 {
		return
	}
	s.observe(ctx, tenantID, SignalDistinctDomains, func(ctx context.Context, key string) (int64, error) {
		return s.counter.AddDistinct(ctx, key, domains, anomalyTTL)
	}, len(domains))
}

// ObserveSharedFailure counts one failed shared job of the organization.
func (s *Service) ObserveSharedFailure(ctx context.Context, tenantID shared.ID) {
	s.observe(ctx, tenantID, SignalFailures, func(ctx context.Context, key string) (int64, error) {
		return s.counter.Incr(ctx, key, 1, anomalyTTL)
	}, 1)
}

// ObserveDenyListHits counts targets of the organization the platform deny
// list refused (on any sensor).
func (s *Service) ObserveDenyListHits(ctx context.Context, tenantID shared.ID, n int) {
	if n <= 0 {
		return
	}
	s.observe(ctx, tenantID, SignalDenyListHits, func(ctx context.Context, key string) (int64, error) {
		return s.counter.Incr(ctx, key, int64(n), anomalyTTL)
	}, n)
}

// observe adds to one signal's daily counter and raises the alert the first
// time the counter reaches the threshold that day. It never fails the
// caller.
func (s *Service) observe(ctx context.Context, tenantID shared.ID, signal string, add func(context.Context, string) (int64, error), n int) {
	if s == nil || s.counter == nil || tenantID.IsZero() {
		return
	}
	if s.metrics != nil {
		s.metrics.ObserveSharedSensorSignal(signal, n)
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), anomalyTimeout)
	defer cancel()
	day := time.Now().UTC().Format("20060102")
	count, err := add(ctx, anomalyKey(signal, tenantID, day))
	if err != nil {
		s.log.Warn("shared sensor anomaly counter failed; signal lost for this event", "signal", signal, "error", err)
		return
	}
	limit := s.thresholds(ctx).of(signal)
	if limit <= 0 || count < int64(limit) {
		return
	}
	first, err := s.counter.Once(ctx, "sharedabuse:alerted:"+signal+":"+tenantID.String()+":"+day, anomalyTTL)
	if err != nil || !first {
		return
	}
	s.raiseAnomaly(ctx, tenantID, signal, count, limit)
}

func anomalyKey(signal string, tenantID shared.ID, day string) string {
	return "sharedabuse:" + signal + ":" + tenantID.String() + ":" + day
}

// raiseAnomaly alerts the administrators: metric, log, admin audit row
// (high), email. It names the organization, never a target.
func (s *Service) raiseAnomaly(ctx context.Context, tenantID shared.ID, signal string, count int64, limit int) {
	if s.metrics != nil {
		s.metrics.ObserveSharedSensorAnomaly(signal)
	}
	s.log.Warn("shared sensor anomaly", "alert", "shared_sensor_anomaly", "signal", signal,
		"tenant_id", tenantID.String(), "count", count, "threshold", limit)
	if s.audit != nil {
		entry := admin.NewAuditLogBuilder(nil, ActionSharedSensorAnomaly).
			Resource("tenant", &tenantID, signal).
			Request("", "", map[string]any{"signal": signal, "count": count, "threshold": limit, "day": time.Now().UTC().Format("2006-01-02")}).
			Build()
		entry.Severity = admin.SeverityHigh
		if err := s.audit.Create(ctx, entry); err != nil {
			s.log.Error("write admin audit for shared sensor anomaly", "error", err)
		}
	}
	s.mailOthers(ctx, Change{}, "[Scans] Shared sensor anomaly",
		fmt.Sprintf("Organization %s reached %d %s on shared sensors today (UTC); the alert threshold is %d. "+
			"Review it in the admin console; you can deny the organization shared sensors there.",
			tenantID, count, signalText(signal), limit))
}

func signalText(signal string) string {
	switch signal {
	case SignalDistinctDomains:
		return "distinct registrable domains"
	case SignalFailures:
		return "failed jobs"
	case SignalDenyListHits:
		return "deny-list hits"
	}
	return signal
}

// registrableDomains returns the distinct registrable domains (eTLD+1) of
// the targets: host names of plain names, host:port and URLs. Addresses,
// ranges and names that have no registrable domain are skipped.
func registrableDomains(targets []string) []string {
	seen := make(map[string]struct{}, len(targets))
	out := make([]string, 0, len(targets))
	for _, t := range targets {
		host := targetHost(t)
		if host == "" || net.ParseIP(host) != nil {
			continue
		}
		d, err := publicsuffix.EffectiveTLDPlusOne(host)
		if err != nil || d == "" {
			continue
		}
		if _, ok := seen[d]; ok {
			continue
		}
		seen[d] = struct{}{}
		out = append(out, d)
	}
	return out
}

func targetHost(t string) string {
	t = strings.TrimSpace(strings.ToLower(t))
	if t == "" || strings.Contains(t, "/") && !strings.Contains(t, "://") {
		return "" // a range or a path target
	}
	if strings.Contains(t, "://") {
		u, err := url.Parse(t)
		if err != nil {
			return ""
		}
		return strings.TrimSuffix(u.Hostname(), ".")
	}
	if h, _, err := net.SplitHostPort(t); err == nil {
		t = h
	}
	t = strings.TrimPrefix(t, "*.")
	return strings.TrimSuffix(t, ".")
}
