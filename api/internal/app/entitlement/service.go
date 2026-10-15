// Package entitlement is the one place that answers what an organization may
// add and use (docs/architecture/limits.md): its effective limits and their
// usage, the check every creation path calls, the feature denies every
// module gate and named-feature seam reads, and the grace a lost feature
// keeps.
//
// Limits and denies come from the instance operator's own rows plus the
// configured sources (limits.Source): none on a self-hosted install, the
// control plane on a hosted service. No row anywhere means unlimited and
// allowed.
//
// Check is fail-closed: when a limit or usage cannot be read, the addition is
// refused. A limit never removes anything that exists.
package entitlement

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/limits"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Admin audit actions.
const (
	ActionSelfServiceDefaultsChanged = "platform.self_service_limits_changed"
	ActionLimitSet                   = "organization.limit_set"
	ActionLimitRemoved               = "organization.limit_removed"
	ActionControlPlaneApplied        = "organization.control_plane_entitlements_applied"
	defaultsCacheTTL                 = 15 * time.Second
	maxReasonRunes                   = 500
)

// ControlPlaneActor is the audit actor of writes made by the control plane.
const ControlPlaneActor = "control-plane"

// AuditWriter writes one admin audit row.
type AuditWriter interface {
	Create(ctx context.Context, log *admin.AuditLog) error
}

// Service serves limits, feature denies and checks.
type Service struct {
	repo    limits.Repository
	sources []limits.Source
	audit   AuditWriter
	log     *logger.Logger
	now     func() time.Time

	mu       sync.Mutex
	cached   limits.Limits
	version  int
	cachedAt time.Time

	modulesChanged ModulesChangeNotifier

	// envStart are the starting limits of self-service organizations from
	// the environment (SELF_SERVICE_START_LIMITS); nil when not set.
	envStart limits.Limits
}

// ErrStartLimitsRequired refuses self-service sign-up while no starting
// limits are configured.
var ErrStartLimitsRequired = errors.New("self-service sign-up needs starting limits: set SELF_SERVICE_START_LIMITS " +
	"(a JSON object of limits, or \"unlimited\" to choose none), save them in Console > System > Limits, " +
	"or turn on the internal entitlements API")

// SetStartLimits reads SELF_SERVICE_START_LIMITS: empty (not configured),
// "unlimited" (configured, no limits) or a JSON object of limit keys.
func (s *Service) SetStartLimits(raw string) error {
	raw = strings.TrimSpace(raw)
	switch {
	case raw == "":
		s.envStart = nil
	case strings.EqualFold(raw, "unlimited"):
		s.envStart = limits.Limits{}
	default:
		l, err := limits.DecodeLimits([]byte(raw))
		if err != nil {
			return fmt.Errorf("SELF_SERVICE_START_LIMITS: %w", err)
		}
		s.envStart = l
	}
	return nil
}

// StartLimitsConfigured reports whether the starting limits of self-service
// organizations are configured: a source (the internal API), the
// environment, or a console setting. Self-service sign-up requires it, so a
// public sign-up can never hand out unlimited organizations by accident.
func (s *Service) StartLimitsConfigured(ctx context.Context) (bool, error) {
	if len(s.sources) > 0 || s.envStart != nil {
		return true, nil
	}
	_, _, err := s.repo.GetSelfServiceDefaults(ctx)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, shared.ErrNotFound) {
		return false, nil
	}
	return false, err
}

// NewService creates the service with no source beyond the operator's own
// rows (the self-hosted default). audit may be nil.
func NewService(repo limits.Repository, audit AuditWriter, log *logger.Logger) *Service {
	if log == nil {
		log = logger.NewNop()
	}
	return &Service{repo: repo, audit: audit, log: log.With("service", "entitlement"), now: time.Now}
}

// SetSources replaces the configured sources (limits.NoneSource when none).
func (s *Service) SetSources(src ...limits.Source) { s.sources = src }

// SourceNames lists the configured sources (the system page shows them).
func (s *Service) SourceNames() []string {
	if len(s.sources) == 0 {
		return []string{limits.NoneSource{}.Name()}
	}
	out := make([]string, 0, len(s.sources))
	for _, src := range s.sources {
		out = append(out, src.Name())
	}
	return out
}

// SelfServiceDefaults returns the limits a new self-service organization
// starts with (empty until an administrator saves some) and their version
// (0: not stored).
func (s *Service) SelfServiceDefaults(ctx context.Context) (limits.Limits, int, error) {
	s.mu.Lock()
	if s.cached != nil && s.now().Sub(s.cachedAt) < defaultsCacheTTL {
		d, v := s.cached, s.version
		s.mu.Unlock()
		return d, v, nil
	}
	s.mu.Unlock()
	d, v, err := s.repo.GetSelfServiceDefaults(ctx)
	if err != nil {
		if !errors.Is(err, shared.ErrNotFound) {
			return nil, 0, err
		}
		d, v = limits.Limits{}, 0
		if s.envStart != nil {
			d = s.envStart
		}
	}
	s.mu.Lock()
	s.cached, s.version, s.cachedAt = d, v, s.now()
	s.mu.Unlock()
	return d, v, nil
}

// Summary is an organization's effective limits, denied features and usage.
type Summary struct {
	Limits    []limits.Effective `json:"limits"`
	Denied    []DeniedFeature    `json:"denied_features"`
	OverLimit bool               `json:"over_limit"`
	// Applies: at least one limit or deny applies. "Usage & limits" is shown
	// only then.
	Applies bool `json:"applies"`
}

// DeniedFeature is one feature the organization may not use.
type DeniedFeature struct {
	Feature string        `json:"feature"`
	Origin  limits.Origin `json:"origin"`
	// ReadOnlyUntil: the organization keeps read access until then.
	ReadOnlyUntil *time.Time `json:"read_only_until,omitempty"`
}

// stored returns every active limit of the organization: the operator's
// rows and the configured sources'. For a key the operator's row wins.
func (s *Service) stored(ctx context.Context, tenantID shared.ID) (map[limits.Key]limits.Limit, error) {
	now := s.now()
	out := map[limits.Key]limits.Limit{}
	for _, src := range s.sources {
		list, err := src.Limits(ctx, tenantID)
		if err != nil {
			return nil, err
		}
		for _, l := range list {
			if l.TenantID == tenantID && l.Key.PerOrganization() && l.Active(now) {
				out[l.Key] = l
			}
		}
	}
	ops, err := s.repo.ListLimits(ctx, tenantID, limits.OriginOperator)
	if err != nil {
		return nil, err
	}
	for _, l := range ops {
		if l.Key.PerOrganization() && l.Active(now) {
			out[l.Key] = l
		}
	}
	return out, nil
}

// limitsOf returns the organization's effective limits, without usage.
func (s *Service) limitsOf(ctx context.Context, tenantID shared.ID) ([]limits.Effective, error) {
	byKey, err := s.stored(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	out := make([]limits.Effective, 0, len(limits.Keys))
	for _, k := range limits.Keys {
		if !k.PerOrganization() {
			continue
		}
		e := limits.Effective{Key: k, Limit: limits.Unlimited}
		if l, ok := byKey[k]; ok {
			e.Limit, e.Origin, e.ExpiresAt, e.Reason = l.Value, l.Origin, l.ExpiresAt, l.Reason
		}
		out = append(out, e)
	}
	return out, nil
}

// Effective returns the organization's limits with their usage and its
// denied features. Findings are counted (a count over the largest table)
// only while a findings limit applies; otherwise that row is Uncounted.
func (s *Service) Effective(ctx context.Context, tenantID shared.ID) (*Summary, error) {
	lims, err := s.limitsOf(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	countFindings := false
	for _, e := range lims {
		if e.Key == limits.Findings {
			countFindings = e.Limit != limits.Unlimited
		}
	}
	usage, err := s.repo.Usage(ctx, tenantID, countFindings)
	if err != nil {
		return nil, err
	}
	denied, err := s.DeniedFeatures(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	sum := &Summary{Limits: lims, Denied: denied, Applies: len(denied) > 0}
	for i := range sum.Limits {
		e := &sum.Limits[i]
		e.Used = usage[e.Key]
		e.Uncounted = e.Key == limits.Findings && !countFindings
		e.OverLimit = e.Limit != limits.Unlimited && e.Used > e.Limit
		sum.OverLimit = sum.OverLimit || e.OverLimit
		sum.Applies = sum.Applies || e.Limit != limits.Unlimited
	}
	return sum, nil
}

// limitAndUsage returns the organization's limit of key and, when it is not
// Unlimited, its usage. An unlimited key costs no usage query.
func (s *Service) limitAndUsage(ctx context.Context, tenantID shared.ID, key limits.Key) (limit, used int, err error) {
	byKey, err := s.stored(ctx, tenantID)
	if err != nil {
		return 0, 0, err
	}
	limit = limits.Unlimited
	if l, ok := byKey[key]; ok {
		limit = l.Value
	}
	if limit == limits.Unlimited {
		return limit, 0, nil
	}
	usage, err := s.repo.Usage(ctx, tenantID, key == limits.Findings)
	if err != nil {
		return 0, 0, err
	}
	return limit, usage[key], nil
}

// Check refuses an addition of delta to key when it would exceed the
// organization's limit: *limits.ErrLimitReached. Any read error refuses too
// (fail-closed). Unlimited never refuses and counts no usage.
func (s *Service) Check(ctx context.Context, tenantID shared.ID, key limits.Key, delta int) error {
	if !key.PerOrganization() {
		return limits.ErrInvalid
	}
	limit, used, err := s.limitAndUsage(ctx, tenantID, key)
	if err != nil {
		s.log.Warn("limit check failed; refusing (fail-closed)", "key", string(key), "error", err)
		return &limits.ErrLimitReached{Key: key, Unavailable: true}
	}
	if limits.AllowAddition(limit, used, delta) {
		return nil
	}
	refusals.WithLabelValues(string(key)).Inc()
	return &limits.ErrLimitReached{Key: key, Limit: limit, Used: used}
}

// Headroom returns how many more of key the organization may add: Unlimited
// when no limit applies (no usage is counted), 0 at or over the limit. When
// the limit or usage cannot be read it returns *limits.ErrLimitReached with
// Unavailable (callers refuse: fail-closed).
func (s *Service) Headroom(ctx context.Context, tenantID shared.ID, key limits.Key) (int, error) {
	if !key.PerOrganization() {
		return 0, limits.ErrInvalid
	}
	limit, used, err := s.limitAndUsage(ctx, tenantID, key)
	if err != nil {
		s.log.Warn("limit headroom failed; refusing (fail-closed)", "key", string(key), "error", err)
		return 0, &limits.ErrLimitReached{Key: key, Unavailable: true}
	}
	if limit == limits.Unlimited {
		return limits.Unlimited, nil
	}
	return max(0, limit-used), nil
}

// RecordRefusals counts n additions of key refused by its limit (a caller
// that refused part of a batch after Headroom).
func (s *Service) RecordRefusals(key limits.Key, n int) {
	if n > 0 {
		refusals.WithLabelValues(string(key)).Add(float64(n))
	}
}

// CheckOrgsPerUser refuses a self-service organization for a person who
// already owns the instance's orgs_per_user (unlimited unless an
// administrator set it in the self-service defaults).
func (s *Service) CheckOrgsPerUser(ctx context.Context, userID shared.ID) error {
	d, _, err := s.SelfServiceDefaults(ctx)
	if err != nil {
		return &limits.ErrLimitReached{Key: limits.OrgsPerUser, Unavailable: true}
	}
	limit := d.Get(limits.OrgsPerUser)
	if limit == limits.Unlimited {
		return nil
	}
	n, err := s.repo.CountOwnedTenants(ctx, userID)
	if err != nil {
		return &limits.ErrLimitReached{Key: limits.OrgsPerUser, Limit: limit, Unavailable: true}
	}
	if !limits.AllowAddition(limit, n, 1) {
		refusals.WithLabelValues(string(limits.OrgsPerUser)).Inc()
		return &limits.ErrLimitReached{Key: limits.OrgsPerUser, Limit: limit, Used: n}
	}
	return nil
}

// UpdateSelfServiceDefaults saves the self-service defaults (the caller
// checked super admin and a fresh authenticator code). Audited at critical
// severity. Existing organizations are not changed.
func (s *Service) UpdateSelfServiceDefaults(ctx context.Context, actor *admin.AdminUser, d limits.Limits, expectedVersion int, ip, ua string) (int, error) {
	if actor == nil {
		return 0, errors.New("changing the self-service defaults needs an administrator")
	}
	if err := d.Validate(); err != nil {
		return 0, err
	}
	id := actor.ID()
	v, err := s.repo.SaveSelfServiceDefaults(ctx, d, expectedVersion, &id, s.now().UTC())
	if err != nil {
		return 0, err
	}
	s.mu.Lock()
	s.cached, s.version, s.cachedAt = d, v, s.now()
	s.mu.Unlock()
	body := map[string]any{"version": v}
	for k, val := range d {
		body[string(k)] = val
	}
	s.writeAudit(ctx, actor, ActionSelfServiceDefaultsChanged, nil, "self_service_default_limits", body, ip, ua)
	s.log.Warn("self-service default limits changed", "alert", ActionSelfServiceDefaultsChanged, "admin_id", actor.ID().String())
	return v, nil
}

// LimitInput is one operator limit for one organization.
type LimitInput struct {
	Key       limits.Key
	Value     int
	Reason    string
	ExpiresAt *time.Time
}

// ValidReason reports a non-blank reason of at most 500 characters.
func ValidReason(reason string) bool {
	r := strings.TrimSpace(reason)
	return r != "" && len([]rune(r)) <= maxReasonRunes
}

// PutLimit sets one operator limit for one organization (audited). A reason
// is required; an expiry, when given, must be in the future.
func (s *Service) PutLimit(ctx context.Context, actor *admin.AdminUser, tenantID shared.ID, in LimitInput, ip, ua string) error {
	now := s.now().UTC()
	if actor == nil || !in.Key.PerOrganization() || in.Value < limits.Unlimited || !ValidReason(in.Reason) ||
		(in.ExpiresAt != nil && !in.ExpiresAt.After(now)) {
		return limits.ErrInvalid
	}
	reason := strings.TrimSpace(in.Reason)
	id := actor.ID()
	l := limits.Limit{TenantID: tenantID, Key: in.Key, Value: in.Value, Origin: limits.OriginOperator,
		Reason: reason, ExpiresAt: in.ExpiresAt, SetBy: &id, SetAt: now}
	if err := s.repo.SetLimit(ctx, l); err != nil {
		return err
	}
	body := map[string]any{"key": string(in.Key), "value": in.Value, "reason": reason}
	if in.ExpiresAt != nil {
		body["expires_at"] = in.ExpiresAt.UTC().Format(time.RFC3339)
	}
	s.writeAudit(ctx, actor, ActionLimitSet, &tenantID, "tenant", body, ip, ua)
	return nil
}

// DeleteLimit removes one operator limit (audited).
func (s *Service) DeleteLimit(ctx context.Context, actor *admin.AdminUser, tenantID shared.ID, key limits.Key, ip, ua string) error {
	if actor == nil || !key.PerOrganization() {
		return limits.ErrInvalid
	}
	if err := s.repo.DeleteLimit(ctx, tenantID, key, limits.OriginOperator); err != nil {
		return err
	}
	s.writeAudit(ctx, actor, ActionLimitRemoved, &tenantID, "tenant", map[string]any{"key": string(key)}, ip, ua)
	return nil
}

func (s *Service) writeAudit(ctx context.Context, actor *admin.AdminUser, action string, id *shared.ID, resource string, body map[string]any, ip, ua string) {
	if s.audit == nil || actor == nil {
		return
	}
	b := admin.NewAuditLogBuilder(actor, action).
		Resource(resource, id, "").
		Context(ip, ua).
		Request("PUT", "", body)
	// A change for every new organization is critical; one organization's
	// limit or deny is high.
	if action == ActionSelfServiceDefaultsChanged {
		b = b.Critical()
	} else {
		b = b.High()
	}
	s.createAudit(ctx, action, b.Build())
}

func (s *Service) createAudit(ctx context.Context, action string, entry *admin.AuditLog) {
	if s.audit == nil {
		return
	}
	actx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if err := s.audit.Create(actx, entry); err != nil {
		s.log.Error("write admin audit", "action", action, "error", err)
	}
}
