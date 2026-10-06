// Package sensorgrant manages per-sensor grants: reading them, narrowing and
// widening them, promoting and demoting the trust level, and the grant a
// pairing approval creates (docs/rfcs/RFC-052-sensor-pairing-and-authorization.md
// §5).
//
// Threat model: an administrator account with only the narrow permission
// must not be able to widen a sensor (insider widening, use case 16); a
// sensor of another tenant must read as not found; two concurrent changes
// must not silently overwrite each other (compare-and-swap on the version).
// Every change is audited with a diff; a widening is audited at high
// severity and notifies every administrator.
package sensorgrant

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	notificationdom "github.com/openctemio/openctem/api/pkg/domain/notification"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Errors.
var (
	// ErrNotFound: no sensor with this id in the tenant.
	ErrNotFound = fmt.Errorf("%w: sensor not found", shared.ErrNotFound)
	// ErrWidenForbidden: the change widens the grant and the actor lacks
	// sensors:grant:widen.
	ErrWidenForbidden = fmt.Errorf("%w: widening a sensor's grant needs the sensors:grant:widen permission", shared.ErrForbidden)
	// ErrNarrowForbidden: the actor has neither grant permission.
	ErrNarrowForbidden = fmt.Errorf("%w: changing a sensor's grant needs the sensors:grant:narrow permission", shared.ErrForbidden)
	// ErrVersionConflict: the grant changed since the caller read it.
	ErrVersionConflict = fmt.Errorf("%w: the sensor's grant changed since it was read; reload and retry", shared.ErrConflict)
	// ErrLegacyProfile: legacy-broad cannot be chosen.
	ErrLegacyProfile = fmt.Errorf("%w: the legacy-broad profile cannot be chosen", shared.ErrValidation)
)

// WideningApprover decides whether a widening may take effect. Today the
// single actor holding sensors:grant:widen approves; a two-person rule
// plugs in here (RFC-052 D-5).
type WideningApprover interface {
	ApproveWidening(ctx context.Context, actor Actor, cur, next sensordom.Grant, widened []string) error
}

// AdminDirectory lists the administrators to notify.
type AdminDirectory interface {
	ActiveAdminIDs(ctx context.Context, tenantID shared.ID) ([]shared.ID, error)
}

// InAppNotifier sends one in-app notification.
type InAppNotifier interface {
	Notify(ctx context.Context, p notificationdom.NotificationParams) error
}

// SensorLookup reads a sensor of a tenant (name for audits, existence).
type SensorLookup interface {
	GetByTenantAndID(ctx context.Context, tenantID, id shared.ID) (*sensordom.Sensor, error)
}

// ZoneChecker confirms that zone ids are the tenant's.
type ZoneChecker interface {
	ZonesInTenant(ctx context.Context, tenantID shared.ID, ids []shared.ID) (bool, error)
}

// Actor is the authenticated user changing a grant, with the grant
// permissions it holds (resolved by the handler from the request).
type Actor struct {
	TenantID  shared.ID
	UserID    shared.ID
	Email     string
	IP        string
	UserAgent string
	SessionID string
	CanNarrow bool
	CanWiden  bool
}

// Service manages grants.
type Service struct {
	repo     sensordom.GrantRepository
	sensors  SensorLookup
	zones    ZoneChecker
	audit    *auditapp.AuditService
	admins   AdminDirectory
	notifier InAppNotifier
	approver WideningApprover
	log      *logger.Logger
}

// NewService builds the grant service.
func NewService(repo sensordom.GrantRepository, sensors SensorLookup, log *logger.Logger) *Service {
	return &Service{repo: repo, sensors: sensors, log: log.With("service", "sensorgrant")}
}

// SetAudit, SetNotifications, SetZoneChecker and SetWideningApprover wire
// the optional collaborators.
func (s *Service) SetAudit(a *auditapp.AuditService) { s.audit = a }
func (s *Service) SetNotifications(d AdminDirectory, n InAppNotifier) {
	s.admins, s.notifier = d, n
}
func (s *Service) SetZoneChecker(z ZoneChecker)           { s.zones = z }
func (s *Service) SetWideningApprover(a WideningApprover) { s.approver = a }

// Get returns the grant of a sensor of the tenant.
func (s *Service) Get(ctx context.Context, tenantID, sensorID shared.ID) (*sensordom.Grant, error) {
	g, err := s.repo.Get(ctx, tenantID, sensorID)
	if errors.Is(err, shared.ErrNotFound) {
		return nil, ErrNotFound
	}
	return g, err
}

// SummaryLister lists the grant summaries of a tenant's sensors.
type SummaryLister interface {
	ListSummaries(ctx context.Context, tenantID shared.ID, limit int) ([]sensordom.GrantSummary, error)
}

// MaxSummaries bounds the summary list (a tenant's whole fleet).
const MaxSummaries = 5000

// SummaryView is one row of the sensor list's grant flags.
type SummaryView struct {
	SensorID    string `json:"sensor_id"`
	Profile     string `json:"profile"`
	TrustLevel  string `json:"trust_level"`
	LegacyBroad bool   `json:"legacy_broad"`
} // @name SensorGrantSummary

// Summaries lists the profile and trust level of every sensor of the
// tenant (empty when the repository cannot list).
func (s *Service) Summaries(ctx context.Context, tenantID shared.ID) ([]SummaryView, error) {
	l, ok := s.repo.(SummaryLister)
	if !ok {
		return []SummaryView{}, nil
	}
	rows, err := l.ListSummaries(ctx, tenantID, MaxSummaries)
	if err != nil {
		return nil, err
	}
	out := make([]SummaryView, 0, len(rows))
	for _, r := range rows {
		out = append(out, SummaryView{SensorID: r.SensorID.String(), Profile: r.Profile, TrustLevel: string(r.TrustLevel),
			LegacyBroad: r.Profile == sensordom.ProfileLegacyBroad})
	}
	return out, nil
}

// UpdateInput is the full new grant (every dimension is replaced). Profile,
// when set, rebuilds every dimension from that profile first (keeping the
// trust level unless TrustLevel is set); the other fields are then ignored.
// Version is the version the caller read (optimistic concurrency).
type UpdateInput struct {
	Version int

	Profile string

	TrustLevel       sensordom.TrustLevel
	JobTypes         []string
	ZoneIDs          []shared.ID
	Tools            []string
	Capabilities     []string
	TierCeiling      int
	TargetNetwork    sensordom.TargetNetwork
	TargetCIDRs      []string
	TargetDomains    []string
	AllowCredentials bool
	AllowPushIngest  bool
	RemoteActions    []string
}

// Update replaces a sensor's grant. A change that widens any dimension
// needs CanWiden (and the widening approver); any other change needs
// CanNarrow or CanWiden.
func (s *Service) Update(ctx context.Context, actor Actor, sensorID shared.ID, in UpdateInput) (*sensordom.Grant, error) {
	if !actor.CanNarrow && !actor.CanWiden {
		return nil, ErrNarrowForbidden
	}
	cur, err := s.Get(ctx, actor.TenantID, sensorID)
	if err != nil {
		return nil, err
	}
	if in.Version != 0 && in.Version != cur.Version {
		return nil, ErrVersionConflict
	}
	next, err := s.build(*cur, in)
	if err != nil {
		return nil, err
	}
	if len(next.ZoneIDs) > 0 && s.zones != nil {
		ok, err := s.zones.ZonesInTenant(ctx, actor.TenantID, next.ZoneIDs)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, fmt.Errorf("%w: unknown zone", shared.ErrValidation)
		}
	}
	changed := sensordom.Changed(*cur, next)
	if len(changed) == 0 && next.Profile == cur.Profile {
		return cur, nil
	}
	widened := sensordom.Widened(*cur, next)
	if len(widened) > 0 {
		if !actor.CanWiden {
			s.logAudit(ctx, actor, auditapp.NewFailureEvent(audit.ActionSensorGrantChanged, audit.ResourceTypeSensor, sensorID.String(), ErrWidenForbidden).
				WithMessage("Sensor grant widening refused: the sensors:grant:widen permission is required").
				WithSeverity(audit.SeverityHigh).WithMetadata("widened", widened))
			return nil, ErrWidenForbidden
		}
		if s.approver != nil {
			if err := s.approver.ApproveWidening(ctx, actor, *cur, next, widened); err != nil {
				return nil, err
			}
		}
	}
	uid := actor.UserID
	next.UpdatedBy = &uid
	next.Version = cur.Version
	ok, err := s.repo.Update(ctx, &next)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrVersionConflict
	}
	next.Version = cur.Version + 1
	s.onChanged(ctx, actor, *cur, next, changed, widened)
	return &next, nil
}

// build computes the next grant from the input.
func (s *Service) build(cur sensordom.Grant, in UpdateInput) (sensordom.Grant, error) {
	if in.Profile != "" {
		if in.Profile == sensordom.ProfileLegacyBroad {
			return sensordom.Grant{}, ErrLegacyProfile
		}
		g, err := sensordom.NewGrantFromProfile(cur.TenantID, cur.SensorID, in.Profile, in.ZoneIDs)
		if err != nil {
			return sensordom.Grant{}, fmt.Errorf("%w: %w", shared.ErrValidation, err)
		}
		g.TrustLevel = cur.TrustLevel
		if in.TrustLevel != "" {
			g.TrustLevel = in.TrustLevel
		}
		if err := g.Normalize(); err != nil {
			return sensordom.Grant{}, fmt.Errorf("%w: %w", shared.ErrValidation, err)
		}
		return *g, nil
	}
	next := sensordom.Grant{
		TenantID: cur.TenantID, SensorID: cur.SensorID, Profile: cur.Profile,
		TrustLevel: in.TrustLevel, JobTypes: in.JobTypes, ZoneIDs: in.ZoneIDs, Tools: in.Tools,
		Capabilities: in.Capabilities, TierCeiling: in.TierCeiling, TargetNetwork: in.TargetNetwork,
		TargetCIDRs: in.TargetCIDRs, TargetDomains: in.TargetDomains, AllowCredentials: in.AllowCredentials,
		AllowPushIngest: in.AllowPushIngest, RemoteActions: in.RemoteActions, CreatedAt: cur.CreatedAt,
	}
	if next.TrustLevel == "" {
		next.TrustLevel = cur.TrustLevel
	}
	if err := next.Normalize(); err != nil {
		return sensordom.Grant{}, fmt.Errorf("%w: %w", shared.ErrValidation, err)
	}
	// A grant edited dimension by dimension is no longer its profile; only
	// a change of the trust level alone keeps the label (legacy-broad
	// included, so the console keeps flagging it).
	if dims := sensordom.Changed(cur, next); len(dims) > 0 && !(len(dims) == 1 && dims[0] == sensordom.DimTrust) {
		next.Profile = sensordom.ProfileCustom
	}
	return next, nil
}

func (s *Service) onChanged(ctx context.Context, actor Actor, cur, next sensordom.Grant, changed, widened []string) {
	name := sensorID(next)
	if s.sensors != nil {
		if sen, err := s.sensors.GetByTenantAndID(ctx, actor.TenantID, next.SensorID); err == nil && sen != nil {
			name = sen.Name
		}
	}
	sev, verb := audit.SeverityMedium, "narrowed"
	if len(widened) > 0 {
		sev, verb = audit.SeverityHigh, "widened"
	}
	msg := fmt.Sprintf("Grant of sensor %q %s by %s (%s)", name, verb, actor.Email, strings.Join(changed, ", "))
	s.logAudit(ctx, actor, auditapp.NewSuccessEvent(audit.ActionSensorGrantChanged, audit.ResourceTypeSensor, next.SensorID.String()).
		WithResourceName(name).WithMessage(msg).WithSeverity(sev).
		WithMetadata("changed", changed).WithMetadata("widened", widened).
		WithMetadata("before", GrantView(cur)).WithMetadata("after", GrantView(next)).
		WithMetadata("version", next.Version))
	if len(widened) > 0 {
		s.notifyAdmins(ctx, actor.TenantID, "Sensor grant widened: "+name, msg)
	}
}

func sensorID(g sensordom.Grant) string { return g.SensorID.String() }

// ---------------------------------------------------------------------------
// Pairing approval hook
// ---------------------------------------------------------------------------

// ValidProfile reports whether profile may be chosen for a new sensor.
func (s *Service) ValidProfile(profile string) bool { return sensordom.ValidProfile(profile) }

// DefaultProfile is the profile an approval uses when none is chosen.
func (s *Service) DefaultProfile() string { return sensordom.DefaultProfile }

// OnApproved returns the step the pairing approval runs in its transaction:
// the sensor's grant becomes the chosen profile at trust level New (a
// re-paired sensor returns to New too).
func (s *Service) OnApproved(tenantID shared.ID, profile string, zones []shared.ID, approvedBy shared.ID) func(ctx context.Context, tx *sql.Tx, sensorID shared.ID, repair bool) error {
	return func(ctx context.Context, tx *sql.Tx, sensorID shared.ID, _ bool) error {
		g, err := sensordom.NewGrantFromProfile(tenantID, sensorID, profile, zones)
		if err != nil {
			return err
		}
		if err := g.Normalize(); err != nil {
			return err
		}
		by := approvedBy
		g.UpdatedBy = &by
		return s.repo.ReplaceTx(ctx, tx, g)
	}
}

// ---------------------------------------------------------------------------
// Views and helpers
// ---------------------------------------------------------------------------

// View is the JSON shape of a grant (API responses and audit diffs).
type View struct {
	SensorID         string   `json:"sensor_id"`
	Profile          string   `json:"profile"`
	LegacyBroad      bool     `json:"legacy_broad"`
	TrustLevel       string   `json:"trust_level"`
	JobTypes         []string `json:"job_types"`
	ZoneIDs          []string `json:"zone_ids"`
	Tools            []string `json:"tools"`
	Capabilities     []string `json:"capabilities"`
	TierCeiling      int      `json:"tier_ceiling"`
	TargetNetwork    string   `json:"target_network"`
	TargetCIDRs      []string `json:"target_cidrs"`
	TargetDomains    []string `json:"target_domains"`
	AllowCredentials bool     `json:"allow_credentials"`
	AllowPushIngest  bool     `json:"allow_push_ingest"`
	RemoteActions    []string `json:"remote_actions"`
	Version          int      `json:"version"`
	UpdatedAt        string   `json:"updated_at,omitempty"`
	// Effective is what applies now, after the trust level.
	Effective *EffectiveView `json:"effective,omitempty"`
} // @name SensorGrant

// EffectiveView is the part of the grant the trust level changes.
type EffectiveView struct {
	TierCeiling      int  `json:"tier_ceiling"`
	AllowCredentials bool `json:"allow_credentials"`
	AllowPushIngest  bool `json:"allow_push_ingest"`
} // @name SensorGrantEffective

// GrantView renders g. nil lists stay null ("no limit").
func GrantView(g sensordom.Grant) View {
	v := View{
		SensorID: g.SensorID.String(), Profile: g.Profile, LegacyBroad: g.LegacyBroad(), TrustLevel: string(g.TrustLevel),
		JobTypes: g.JobTypes, Tools: g.Tools, Capabilities: g.Capabilities, TierCeiling: g.TierCeiling,
		TargetNetwork: string(g.TargetNetwork), TargetCIDRs: g.TargetCIDRs, TargetDomains: g.TargetDomains,
		AllowCredentials: g.AllowCredentials, AllowPushIngest: g.AllowPushIngest, RemoteActions: g.RemoteActions,
		Version: g.Version,
	}
	if g.ZoneIDs != nil {
		v.ZoneIDs = make([]string, len(g.ZoneIDs))
		for i, z := range g.ZoneIDs {
			v.ZoneIDs[i] = z.String()
		}
	}
	if !g.UpdatedAt.IsZero() {
		v.UpdatedAt = g.UpdatedAt.UTC().Format(time.RFC3339)
	}
	e := g.Effective()
	v.Effective = &EffectiveView{TierCeiling: e.TierCeiling, AllowCredentials: e.AllowCredentials, AllowPushIngest: e.AllowPushIngest}
	return v
}

// ProfileView describes a selectable profile for the console.
type ProfileView struct {
	Name             string   `json:"name"`
	JobTypes         []string `json:"job_types"`
	TierCeiling      int      `json:"tier_ceiling"`
	TargetNetwork    string   `json:"target_network"`
	AllowCredentials bool     `json:"allow_credentials"`
	AllowPushIngest  bool     `json:"allow_push_ingest"`
	Default          bool     `json:"default"`
	// Parameterised: the name takes ":<integration>" (collector).
	Parameterised bool `json:"parameterised"`
} // @name SensorGrantProfile

// Profiles lists the selectable profiles.
func Profiles() []ProfileView {
	out := make([]ProfileView, 0, len(sensordom.SelectableProfiles()))
	for _, p := range sensordom.SelectableProfiles() {
		g, err := sensordom.NewGrantFromProfile(shared.ID{}, shared.ID{}, p, nil)
		if err != nil {
			continue
		}
		out = append(out, ProfileView{
			Name: p, JobTypes: g.JobTypes, TierCeiling: g.TierCeiling, TargetNetwork: string(g.TargetNetwork),
			AllowCredentials: g.AllowCredentials, AllowPushIngest: g.AllowPushIngest,
			Default: p == sensordom.DefaultProfile, Parameterised: p == sensordom.ProfileCollector,
		})
	}
	return out
}

func (s *Service) logAudit(ctx context.Context, a Actor, ev auditapp.AuditEvent) {
	if s.audit == nil {
		return
	}
	actx := auditapp.AuditContext{TenantID: a.TenantID.String(), ActorID: a.UserID.String(), ActorEmail: a.Email,
		ActorIP: a.IP, UserAgent: a.UserAgent, SessionID: a.SessionID}
	if err := s.audit.LogEvent(ctx, actx, ev); err != nil {
		s.log.Warn("sensor grant audit failed", "error", err)
	}
}

func (s *Service) notifyAdmins(ctx context.Context, tenantID shared.ID, title, body string) {
	if s.admins == nil || s.notifier == nil {
		return
	}
	ids, err := s.admins.ActiveAdminIDs(ctx, tenantID)
	if err != nil {
		s.log.Warn("list admins for sensor grant notice", "error", err)
		return
	}
	for _, id := range ids {
		uid := id
		if err := s.notifier.Notify(ctx, notificationdom.NotificationParams{
			TenantID: tenantID, Audience: notificationdom.AudienceUser, AudienceID: &uid,
			NotificationType: notificationdom.TypeSensorSecurity, Title: title, Body: body, Severity: "high",
			ResourceType: "sensor", URL: "/sensors",
		}); err != nil {
			s.log.Warn("notify admin of sensor grant change", "error", err)
		}
	}
}
