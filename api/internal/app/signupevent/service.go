// Package signupevent records sign-up events and raises burst alerts for the
// platform console (docs/architecture/signup-activity.md).
//
// Every account created, organization created and access request submitted
// writes one event holding the registrable email domain and the client
// network prefix (/24 for IPv4, /48 for IPv6) only. Self-service events are
// also counted in Redis per kind, per prefix and per domain, in fixed windows;
// the first time a count reaches its threshold in a window the platform
// raises one alert: a metric (labeled by dimension and kind only), a warning
// log line with alert=signup_burst, a high severity admin audit row and an
// email to the active platform administrators. The thresholds are an instance
// setting (console, super admin, step-up, reason, audit); 0 turns a dimension
// off.
//
// Threat model: the alert is detective, not preventive. The preventive
// controls (sign-up policy and ceiling, CAPTCHA, email verification,
// disposable-domain block, rate limits) never read it, so recording is best
// effort: a failed insert or a missing counter store is logged and never
// fails or holds up a sign-up (each event has a short, bounded budget). No
// tenant route reads or resets the events or the counters.
package signupevent

import (
	"context"
	"errors"
	"fmt"
	"html"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	dom "github.com/openctemio/openctem/api/pkg/domain/signupevent"
	"github.com/openctemio/openctem/api/pkg/httpsec"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Admin audit actions.
const (
	ActionBurst             = "platform.signup_burst"
	ActionThresholdsChanged = "platform.signup_burst_thresholds_changed"
)

// AlertBurst is the stable "alert" field of the WARN line of a burst.
const AlertBurst = "signup_burst"

// Burst dimensions (metric label values).
const (
	DimensionIPPrefix    = "ip_prefix"
	DimensionEmailDomain = "email_domain"
)

// Retention is how long events are kept.
const Retention = 90 * 24 * time.Hour

// recordBudget bounds one event (insert, counters, alert): a sign-up never
// waits longer on its event.
const recordBudget = 3 * time.Second

// cacheTTL bounds how long a replica serves thresholds it read.
const cacheTTL = 15 * time.Second

// Counter keeps the window counters across API replicas (Redis). Every key
// carries the window; it sets ttl on each.
type Counter interface {
	Incr(ctx context.Context, key string, n int64, ttl time.Duration) (int64, error)
	// Once reports true the first time it is called for key.
	Once(ctx context.Context, key string, ttl time.Duration) (bool, error)
}

// Metrics records events and alerts as aggregate metrics (fixed labels,
// never a domain or a prefix).
type Metrics interface {
	ObserveSignupEvent(kind, source string)
	ObserveSignupBurst(dimension, kind string)
}

// Notifier emails the active platform administrators (best effort).
type Notifier interface {
	NotifyAdmins(ctx context.Context, subject, htmlBody string) error
}

// Change is one thresholds change by an administrator.
type Change struct {
	Actor     *admin.AdminUser
	Reason    string
	IP        string
	UserAgent string
}

// Service records sign-up events and serves them to the console.
type Service struct {
	repo     dom.Repository
	settings dom.ThresholdsStore
	audit    admin.AuditLogRepository
	log      *logger.Logger
	now      func() time.Time

	counter  Counter
	metrics  Metrics
	notifier Notifier

	mu       sync.Mutex
	cached   *dom.BurstThresholds
	cachedAt time.Time
}

// NewService creates the service. audit may be nil (tests).
func NewService(repo dom.Repository, settings dom.ThresholdsStore, audit admin.AuditLogRepository, log *logger.Logger) *Service {
	if log == nil {
		log = logger.NewNop()
	}
	return &Service{repo: repo, settings: settings, audit: audit, log: log.With("service", "signup_events"), now: time.Now}
}

// SetBurstCounter wires the counter store and the metrics. Without a store
// the burst alerts are off; events are still recorded.
func (s *Service) SetBurstCounter(c Counter, m Metrics) { s.counter, s.metrics = c, m }

// SetNotifier wires the administrators' email.
func (s *Service) SetNotifier(n Notifier) { s.notifier = n }

// SetClock replaces the clock (tests).
func (s *Service) SetClock(now func() time.Time) { s.now = now }

var _ dom.Recorder = (*Service)(nil)

// Record stores one event and counts it toward the burst alerts. It never
// fails the caller: errors are logged.
func (s *Service) Record(ctx context.Context, e dom.Event) {
	if s == nil || s.repo == nil || !e.Kind.Valid() {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), recordBudget)
	defer cancel()
	r := dom.Record{
		Kind: e.Kind, Source: e.Source, EmailDomain: dom.EmailDomain(e.Email),
		OccurredAt: s.now().UTC(),
	}
	// Only the person signing up has an address worth keeping; an operator
	// action would record the operator's own network.
	if e.Source.SelfService() {
		r.IPPrefix = dom.IPPrefix(httpsec.ClientIPFromContext(ctx))
	}
	if !e.TenantID.IsZero() {
		id := e.TenantID
		r.TenantID = &id
	}
	if !e.UserID.IsZero() {
		id := e.UserID
		r.UserID = &id
	}
	if s.metrics != nil {
		s.metrics.ObserveSignupEvent(string(r.Kind), string(r.Source))
	}
	if err := s.repo.Insert(ctx, r); err != nil {
		s.log.Warn("sign-up event not recorded", "kind", r.Kind, "source", r.Source, "error", logger.SanitizeError(err))
	}
	if e.Source.SelfService() {
		s.observe(ctx, r)
	}
}

// observe counts the event per prefix and per domain and raises the alert
// the first time a count reaches its threshold in the window.
func (s *Service) observe(ctx context.Context, r dom.Record) {
	if s.counter == nil {
		return
	}
	t := s.thresholds(ctx)
	window := time.Duration(t.WindowMinutes) * time.Minute
	if window <= 0 {
		return
	}
	bucket := strconv.FormatInt(r.OccurredAt.Unix()/int64(window/time.Second), 10)
	ttl := 2 * window
	check := func(dimension, value string, limit int) {
		if value == "" || limit <= 0 {
			return
		}
		key := "signupburst:" + dimension + ":" + string(r.Kind) + ":" + value + ":" + bucket
		count, err := s.counter.Incr(ctx, key, 1, ttl)
		if err != nil {
			s.log.Warn("sign-up burst counter failed; signal lost for this event", "dimension", dimension, "error", logger.SanitizeError(err))
			return
		}
		if count < int64(limit) {
			return
		}
		first, err := s.counter.Once(ctx, "signupburst:alerted:"+dimension+":"+string(r.Kind)+":"+value+":"+bucket, ttl)
		if err != nil || !first {
			return
		}
		s.raise(ctx, dimension, value, r.Kind, count, limit, t.WindowMinutes)
	}
	check(DimensionIPPrefix, r.IPPrefix, t.PerIPPrefix)
	if !t.Ignores(r.EmailDomain) {
		check(DimensionEmailDomain, r.EmailDomain, t.PerEmailDomain)
	}
}

// raise alerts the administrators: metric, log, admin audit row (high),
// email. It names the prefix or the domain, never a person.
func (s *Service) raise(ctx context.Context, dimension, value string, kind dom.Kind, count int64, limit, windowMinutes int) {
	if s.metrics != nil {
		s.metrics.ObserveSignupBurst(dimension, string(kind))
	}
	s.log.Warn("sign-up burst", "alert", AlertBurst, "dimension", dimension, "value", value, "kind", string(kind),
		"count", count, "threshold", limit, "window_minutes", windowMinutes)
	if s.audit != nil {
		entry := admin.NewAuditLogBuilder(nil, ActionBurst).
			Resource("signup_burst", nil, value).
			Request("", "", map[string]any{"dimension": dimension, "value": value, "kind": string(kind),
				"count": count, "threshold": limit, "window_minutes": windowMinutes}).
			Build()
		entry.Severity = admin.SeverityHigh
		if err := s.audit.Create(ctx, entry); err != nil {
			s.log.Error("write admin audit for sign-up burst", "error", logger.SanitizeError(err))
		}
	}
	if s.notifier == nil {
		return
	}
	what := map[string]string{DimensionIPPrefix: "network " + value, DimensionEmailDomain: "email domain " + value}[dimension]
	subject := fmt.Sprintf("Sign-up burst: %d %s from one %s", count, kindText(kind), dimensionText(dimension))
	body := fmt.Sprintf("<p>%d %s came from %s within %d minutes; the alert threshold is %d.</p>"+
		"<p>Review the recent sign-ups in the platform console (Requests &gt; Sign-ups). "+
		"You can tighten the sign-up policy there, and suspend organizations that are abusing the service.</p>",
		count, html.EscapeString(kindText(kind)), html.EscapeString(what), windowMinutes, limit)
	if err := s.notifier.NotifyAdmins(ctx, subject, body); err != nil {
		s.log.Warn("sign-up burst email failed", "error", logger.SanitizeError(err))
	}
}

func kindText(k dom.Kind) string {
	switch k {
	case dom.KindAccountCreated:
		return "new accounts"
	case dom.KindOrganizationCreated:
		return "new organizations"
	case dom.KindAccessRequested:
		return "access requests"
	}
	return string(k)
}

func dimensionText(d string) string {
	if d == DimensionIPPrefix {
		return "network"
	}
	return "email domain"
}

// Thresholds returns the thresholds and their version (0: nothing stored,
// the defaults apply).
func (s *Service) Thresholds(ctx context.Context) (dom.BurstThresholds, int, error) {
	if s.settings == nil {
		return dom.DefaultBurstThresholds(), 0, nil
	}
	t, ver, err := s.settings.GetBurstThresholds(ctx)
	if errors.Is(err, dom.ErrThresholdsNotFound) {
		return dom.DefaultBurstThresholds(), 0, nil
	}
	if err != nil {
		return dom.BurstThresholds{}, 0, err
	}
	return t, ver, nil
}

// thresholds is Thresholds cached briefly; an unreadable setting falls back
// to the defaults (the alerts stay on).
func (s *Service) thresholds(ctx context.Context) dom.BurstThresholds {
	s.mu.Lock()
	if s.cached != nil && time.Since(s.cachedAt) < cacheTTL {
		t := *s.cached
		s.mu.Unlock()
		return t
	}
	s.mu.Unlock()
	t, _, err := s.Thresholds(ctx)
	if err != nil {
		s.log.Warn("sign-up burst thresholds unreadable; using the defaults", "error", logger.SanitizeError(err))
		t = dom.DefaultBurstThresholds()
	}
	s.mu.Lock()
	s.cached, s.cachedAt = &t, time.Now()
	s.mu.Unlock()
	return t
}

// UpdateThresholds changes the thresholds. The caller checked super_admin
// and a step-up; the change is audited (critical) and the administrators are
// emailed.
func (s *Service) UpdateThresholds(ctx context.Context, t dom.BurstThresholds, expectedVersion int, c Change) (dom.BurstThresholds, int, error) {
	if c.Actor == nil {
		return dom.BurstThresholds{}, 0, fmt.Errorf("%w: a platform administrator changes the thresholds", shared.ErrForbidden)
	}
	reason := strings.TrimSpace(c.Reason)
	if reason == "" || len(reason) > 1000 {
		return dom.BurstThresholds{}, 0, fmt.Errorf("%w: a reason (at most 1000 characters) is required", shared.ErrValidation)
	}
	t = t.Normalize()
	if err := t.Validate(); err != nil {
		return dom.BurstThresholds{}, 0, err
	}
	if s.settings == nil {
		return dom.BurstThresholds{}, 0, errors.New("the sign-up burst thresholds store is not wired")
	}
	prev, _, err := s.Thresholds(ctx)
	if err != nil {
		return dom.BurstThresholds{}, 0, err
	}
	v, err := s.settings.SetBurstThresholds(ctx, t, expectedVersion, c.Actor.ID().String(), s.now().UTC())
	if err != nil {
		return dom.BurstThresholds{}, 0, err
	}
	s.mu.Lock()
	s.cached, s.cachedAt = &t, time.Now()
	s.mu.Unlock()

	from, to := thresholdsText(prev), thresholdsText(t)
	s.log.Warn("sign-up burst thresholds changed", "alert", "signup_burst_thresholds_changed",
		"admin_id", c.Actor.ID().String(), "from", from, "to", to)
	if s.audit != nil {
		entry := admin.NewAuditLogBuilder(c.Actor, ActionThresholdsChanged).
			Resource("platform_setting", nil, dom.ThresholdsSettingKey).
			Context(c.IP, c.UserAgent).
			Request("PUT", "", map[string]any{"from": from, "to": to, "reason": reason}).
			Critical().
			Build()
		actx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		if err := s.audit.Create(actx, entry); err != nil {
			s.log.Error("write admin audit for sign-up burst thresholds change", "error", logger.SanitizeError(err))
		}
	}
	if s.notifier != nil {
		body := fmt.Sprintf("<p>%s changed the sign-up burst thresholds from %s to %s.</p><p>Reason: %s</p>",
			html.EscapeString(c.Actor.Email()), html.EscapeString(from), html.EscapeString(to), html.EscapeString(reason))
		if err := s.notifier.NotifyAdmins(ctx, "Sign-up burst thresholds changed", body); err != nil {
			s.log.Warn("sign-up burst thresholds email failed", "error", logger.SanitizeError(err))
		}
	}
	return t, v, nil
}

func thresholdsText(t dom.BurstThresholds) string {
	return fmt.Sprintf("per network %d, per email domain %d, window %d min, %d ignored domains",
		t.PerIPPrefix, t.PerEmailDomain, t.WindowMinutes, len(t.IgnoredDomains))
}

// MaxListLimit bounds one page of events.
const MaxListLimit = 100

// List returns a page of events, newest first, and the total.
func (s *Service) List(ctx context.Context, f dom.Filter) ([]dom.Record, int64, error) {
	if f.Kind != "" && !f.Kind.Valid() {
		return nil, 0, fmt.Errorf("%w: unknown kind", shared.ErrValidation)
	}
	if f.Limit <= 0 || f.Limit > MaxListLimit {
		f.Limit = MaxListLimit
	}
	if f.Offset < 0 {
		f.Offset = 0
	}
	return s.repo.List(ctx, f)
}

// MaxDays bounds the daily counts (the retention).
const MaxDays = 90

// Daily returns the events per kind per UTC day for the last days days
// (today included).
func (s *Service) Daily(ctx context.Context, days int) ([]dom.DailyCount, error) {
	if days <= 0 || days > MaxDays {
		days = 30
	}
	now := s.now().UTC()
	since := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC).AddDate(0, 0, -(days - 1))
	return s.repo.Daily(ctx, since)
}

// Purge deletes the events older than the retention.
func (s *Service) Purge(ctx context.Context) (int64, error) {
	return s.repo.Purge(ctx, s.now().UTC().Add(-Retention))
}
