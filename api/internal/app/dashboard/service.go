// Package dashboard is the application service for customizable dashboards
// (docs/architecture/dashboards.md, docs/rfcs/RFC-021-customizable-dashboards.md).
//
// Two kinds share one model:
//   - personal dashboards belong to the caller: every personal operation is
//     scoped to the authenticated (tenant, user), never to a request body;
//     sharing one sends a copy of its layout, never data or access;
//   - organization dashboards belong to the organization: reading needs
//     dashboards:org:view and the dashboard's audience (if it has one),
//     every change needs dashboards:org:manage and is audited.
//
// The routes gate on the same permissions; the service checks them again so
// a new caller cannot skip them.
package dashboard

import (
	"context"
	"errors"
	"fmt"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	domain "github.com/openctemio/openctem/api/pkg/domain/dashboard"
	"github.com/openctemio/openctem/api/pkg/domain/limits"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// AuditLogger records dashboard changes.
type AuditLogger interface {
	LogEvent(ctx context.Context, actx auditapp.AuditContext, event auditapp.AuditEvent) error
}

// LimitReader reads an organization's limit (the entitlement service).
type LimitReader interface {
	Limit(ctx context.Context, tenantID shared.ID, key limits.Key) (int, error)
}

// MembershipReader reads a membership (the tenant repository).
type MembershipReader interface {
	GetMembership(ctx context.Context, userID shared.ID, tenantID shared.ID) (*tenantdom.Membership, error)
}

// SettingsStore reads and writes the organization's dashboard defaults (the
// tenant service).
type SettingsStore interface {
	GetDashboardSettings(ctx context.Context, tenantID string) (*tenantdom.DashboardSettings, error)
	UpdateDashboardSettings(ctx context.Context, tenantID string, ds tenantdom.DashboardSettings, actx auditapp.AuditContext) (*tenantdom.DashboardSettings, error)
}

// Caller is the authenticated caller of an operation.
type Caller struct {
	TenantID shared.ID
	UserID   shared.ID
	// Has reports whether the caller holds a permission (admins hold all).
	Has   func(permission string) bool
	Audit auditapp.AuditContext
}

func (c Caller) has(p permission.Permission) bool { return c.Has != nil && c.Has(p.String()) }

// ErrForbidden is returned when the caller lacks the permission an
// operation needs.
var ErrForbidden = fmt.Errorf("%w: this needs a permission you do not have", shared.ErrForbidden)

// Service provides dashboard operations.
type Service struct {
	repo     domain.Repository
	limits   LimitReader
	members  MembershipReader
	settings SettingsStore
	audit    AuditLogger
	log      *logger.Logger
	now      func() time.Time
}

// NewService creates a dashboard Service.
func NewService(repo domain.Repository, log *logger.Logger) *Service {
	if log == nil {
		log = logger.NewNop()
	}
	return &Service{repo: repo, log: log, now: time.Now}
}

// SetAuditService wires the audit trail.
func (s *Service) SetAuditService(a AuditLogger) { s.audit = a }

// SetLimitReader wires the refresh floor (limit dashboard_refresh_floor_minutes).
func (s *Service) SetLimitReader(l LimitReader) { s.limits = l }

// SetMembershipReader wires the membership check of layout sharing.
func (s *Service) SetMembershipReader(m MembershipReader) { s.members = m }

// SetSettingsStore wires the organization's dashboard defaults.
func (s *Service) SetSettingsStore(st SettingsStore) { s.settings = st }

// CreateInput carries the fields for creating or replacing a dashboard.
type CreateInput struct {
	Name        string
	Description string
	Columns     int
	Widgets     []domain.Widget
}

// ScheduleInput is a refresh schedule to set.
type ScheduleInput struct {
	Interval    domain.Interval
	DailyMinute *int
}

// ---------------------------------------------------------------------------
// Personal dashboards
// ---------------------------------------------------------------------------

// List returns every personal dashboard owned by the caller.
func (s *Service) List(ctx context.Context, tenantID, userID string) ([]*domain.Dashboard, error) {
	tID, uID, err := parseScope(tenantID, userID)
	if err != nil {
		return nil, err
	}
	return s.repo.ListByUser(ctx, tID, uID)
}

// Get returns one of the caller's personal dashboards.
func (s *Service) Get(ctx context.Context, tenantID, userID, id string) (*domain.Dashboard, error) {
	tID, uID, err := parseScope(tenantID, userID)
	if err != nil {
		return nil, err
	}
	dID, err := parseID(id)
	if err != nil {
		return nil, err
	}
	return s.repo.GetByID(ctx, tID, uID, dID)
}

// Create persists a new personal dashboard for the caller.
func (s *Service) Create(ctx context.Context, tenantID, userID string, in CreateInput) (*domain.Dashboard, error) {
	tID, uID, err := parseScope(tenantID, userID)
	if err != nil {
		return nil, err
	}
	d, err := domain.NewDashboard(tID, uID, in.Name, in.Description, in.Columns, in.Widgets)
	if err != nil {
		return nil, err
	}
	if err := s.personalRoom(ctx, tID, uID); err != nil {
		return nil, err
	}
	if err := s.repo.Create(ctx, d); err != nil {
		return nil, err
	}
	return d, nil
}

// Update replaces the name and layout of one of the caller's personal
// dashboards.
func (s *Service) Update(ctx context.Context, tenantID, userID, id string, in CreateInput) (*domain.Dashboard, error) {
	tID, uID, err := parseScope(tenantID, userID)
	if err != nil {
		return nil, err
	}
	dID, err := parseID(id)
	if err != nil {
		return nil, err
	}
	d, err := s.repo.GetByID(ctx, tID, uID, dID)
	if err != nil {
		return nil, err
	}
	if err := d.Update(in.Name, in.Description, in.Columns, in.Widgets); err != nil {
		return nil, err
	}
	if err := s.repo.Update(ctx, d); err != nil {
		return nil, err
	}
	return d, nil
}

// Delete removes one of the caller's personal dashboards.
func (s *Service) Delete(ctx context.Context, tenantID, userID, id string) error {
	tID, uID, err := parseScope(tenantID, userID)
	if err != nil {
		return err
	}
	dID, err := parseID(id)
	if err != nil {
		return err
	}
	return s.repo.Delete(ctx, tID, uID, dID)
}

// SetDefault marks one of the caller's personal dashboards as their default.
func (s *Service) SetDefault(ctx context.Context, tenantID, userID, id string) error {
	tID, uID, err := parseScope(tenantID, userID)
	if err != nil {
		return err
	}
	dID, err := parseID(id)
	if err != nil {
		return err
	}
	return s.repo.SetDefault(ctx, tID, uID, dID)
}

// SetPersonalSchedule sets the refresh schedule of one of the caller's
// personal dashboards (owner only, not audited: it changes nothing anyone
// else sees).
func (s *Service) SetPersonalSchedule(ctx context.Context, c Caller, id string, in ScheduleInput) (*domain.Dashboard, error) {
	if err := c.requireUser(); err != nil {
		return nil, err
	}
	dID, err := parseID(id)
	if err != nil {
		return nil, err
	}
	sch, err := s.validSchedule(ctx, c.TenantID, in)
	if err != nil {
		return nil, err
	}
	if err := s.repo.SetSchedule(ctx, c.TenantID, c.UserID, dID, sch, sch.Next(s.now())); err != nil {
		return nil, err
	}
	return s.repo.GetByID(ctx, c.TenantID, c.UserID, dID)
}

// ShareResult says which recipients got a copy.
type ShareResult struct {
	Shared  []shared.ID
	Skipped []SkippedRecipient
}

// SkippedRecipient is a recipient who got no copy, and why.
type SkippedRecipient struct {
	UserID shared.ID
	Reason string // not_a_member, limit_reached, self
}

// SharePersonal sends a copy of the layout of one of the caller's personal
// dashboards to other active members of the organization. Each recipient
// gets a new personal dashboard of their own (origin "shared"), computed for
// their own data scope: no data, schedule or access travels with it, and the
// caller's dashboard stays theirs.
func (s *Service) SharePersonal(ctx context.Context, c Caller, id string, recipients []shared.ID) (*ShareResult, error) {
	if err := c.requireUser(); err != nil {
		return nil, err
	}
	if len(recipients) == 0 || len(recipients) > domain.MaxShareRecipients {
		return nil, fmt.Errorf("%w: share with 1 to %d members at a time", shared.ErrValidation, domain.MaxShareRecipients)
	}
	if s.members == nil {
		return nil, fmt.Errorf("dashboard sharing is not configured")
	}
	dID, err := parseID(id)
	if err != nil {
		return nil, err
	}
	src, err := s.repo.GetByID(ctx, c.TenantID, c.UserID, dID)
	if err != nil {
		return nil, err
	}
	res := &ShareResult{Shared: []shared.ID{}, Skipped: []SkippedRecipient{}}
	seen := map[shared.ID]bool{}
	for _, uid := range recipients {
		if seen[uid] {
			continue
		}
		seen[uid] = true
		if uid == c.UserID {
			res.Skipped = append(res.Skipped, SkippedRecipient{UserID: uid, Reason: "self"})
			continue
		}
		m, err := s.members.GetMembership(ctx, uid, c.TenantID)
		if err != nil || m == nil || !m.IsActive() {
			res.Skipped = append(res.Skipped, SkippedRecipient{UserID: uid, Reason: "not_a_member"})
			continue
		}
		if _, err := s.copyTo(ctx, src, c.TenantID, uid, domain.OriginShared); err != nil {
			if errors.Is(err, domain.ErrPersonalLimit) {
				res.Skipped = append(res.Skipped, SkippedRecipient{UserID: uid, Reason: "limit_reached"})
				continue
			}
			return nil, err
		}
		res.Shared = append(res.Shared, uid)
	}
	if len(res.Shared) > 0 {
		ids := make([]string, len(res.Shared))
		for i, u := range res.Shared {
			ids[i] = u.String()
		}
		s.logAudit(ctx, c, auditapp.NewSuccessEvent(auditdom.ActionDashboardLayoutShared, auditdom.ResourceTypeDashboard, src.ID().String()).
			WithResourceName(src.Name()).
			WithMessage("Dashboard layout shared (a copy for each recipient, no data)").
			WithMetadata("kind", string(src.Kind())).
			WithMetadata("recipients", ids))
	}
	return res, nil
}

// ---------------------------------------------------------------------------
// Organization dashboards
// ---------------------------------------------------------------------------

// OrgDashboard is an organization dashboard with what the caller may see of
// its audience (managers only).
type OrgDashboard struct {
	*domain.Dashboard
	// Audience is set for managers; nil for viewers.
	Audience []domain.AudienceEntry
}

// ListOrg lists the organization dashboards the caller may see: managers see
// every one (with its audience), viewers those whose audience admits them.
func (s *Service) ListOrg(ctx context.Context, c Caller) ([]OrgDashboard, error) {
	if err := c.requireUser(); err != nil {
		return nil, err
	}
	if !c.has(permission.DashboardsOrgView) && !c.has(permission.DashboardsOrgManage) {
		return nil, ErrForbidden
	}
	if c.has(permission.DashboardsOrgManage) {
		items, err := s.repo.ListOrg(ctx, c.TenantID)
		if err != nil {
			return nil, err
		}
		out := make([]OrgDashboard, 0, len(items))
		for _, d := range items {
			aud, err := s.repo.Audience(ctx, c.TenantID, d.ID())
			if err != nil {
				return nil, err
			}
			out = append(out, OrgDashboard{Dashboard: d, Audience: aud})
		}
		return out, nil
	}
	items, err := s.repo.ListOrgVisible(ctx, c.TenantID, c.UserID)
	if err != nil {
		return nil, err
	}
	out := make([]OrgDashboard, 0, len(items))
	for _, d := range items {
		out = append(out, OrgDashboard{Dashboard: d})
	}
	return out, nil
}

// GetOrg returns one organization dashboard the caller may see. Outside its
// audience it is not found (never forbidden), so its existence does not leak.
func (s *Service) GetOrg(ctx context.Context, c Caller, id string) (*OrgDashboard, error) {
	d, err := s.readableOrg(ctx, c, id)
	if err != nil {
		return nil, err
	}
	out := &OrgDashboard{Dashboard: d}
	if c.has(permission.DashboardsOrgManage) {
		if out.Audience, err = s.repo.Audience(ctx, c.TenantID, d.ID()); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// CreateOrg creates an organization dashboard.
func (s *Service) CreateOrg(ctx context.Context, c Caller, in CreateInput) (*OrgDashboard, error) {
	if err := c.requireManager(); err != nil {
		return nil, err
	}
	d, err := domain.NewOrgDashboard(c.TenantID, in.Name, in.Description, in.Columns, in.Widgets)
	if err != nil {
		return nil, err
	}
	n, err := s.repo.CountOrg(ctx, c.TenantID)
	if err != nil {
		return nil, err
	}
	if n >= domain.MaxOrgPerTenant {
		return nil, domain.ErrOrgLimit
	}
	if err := s.repo.Create(ctx, d); err != nil {
		return nil, err
	}
	s.logAudit(ctx, c, s.orgEvent(auditdom.ActionDashboardOrgCreated, d, "Organization dashboard created").
		WithMetadata("widgets", len(d.Widgets())))
	return s.GetOrg(ctx, c, d.ID().String())
}

// UpdateOrg replaces the name, description, columns and layout of an
// organization dashboard.
func (s *Service) UpdateOrg(ctx context.Context, c Caller, id string, in CreateInput) (*OrgDashboard, error) {
	d, err := s.managedOrg(ctx, c, id)
	if err != nil {
		return nil, err
	}
	before := map[string]any{"name": d.Name(), "description": d.Description(), "columns": d.Columns(), "widgets": len(d.Widgets())}
	if err := d.Update(in.Name, in.Description, in.Columns, in.Widgets); err != nil {
		return nil, err
	}
	if err := s.repo.Update(ctx, d); err != nil {
		return nil, err
	}
	after := map[string]any{"name": d.Name(), "description": d.Description(), "columns": d.Columns(), "widgets": len(d.Widgets())}
	s.logAudit(ctx, c, s.orgEvent(auditdom.ActionDashboardOrgUpdated, d, "Organization dashboard updated").
		WithChanges(auditapp.DiffChanges(before, after)))
	return s.GetOrg(ctx, c, id)
}

// DeleteOrg deletes an organization dashboard.
func (s *Service) DeleteOrg(ctx context.Context, c Caller, id string) error {
	d, err := s.managedOrg(ctx, c, id)
	if err != nil {
		return err
	}
	if err := s.repo.DeleteOrg(ctx, c.TenantID, d.ID()); err != nil {
		return err
	}
	s.logAudit(ctx, c, s.orgEvent(auditdom.ActionDashboardOrgDeleted, d, "Organization dashboard deleted").
		WithMetadata("was_default", d.IsOrgDefault()))
	return nil
}

// SetOrgDefault makes an organization dashboard the organization default
// (the landing dashboard of organization viewers).
func (s *Service) SetOrgDefault(ctx context.Context, c Caller, id string) error {
	d, err := s.managedOrg(ctx, c, id)
	if err != nil {
		return err
	}
	if err := s.repo.SetOrgDefault(ctx, c.TenantID, d.ID()); err != nil {
		return err
	}
	s.logAudit(ctx, c, s.orgEvent(auditdom.ActionDashboardOrgDefaultSet, d, "Organization default dashboard set"))
	return nil
}

// ReorderOrg sets the order of the organization dashboards. ids must list
// every one exactly once.
func (s *Service) ReorderOrg(ctx context.Context, c Caller, ids []string) error {
	if err := c.requireManager(); err != nil {
		return err
	}
	if len(ids) == 0 || len(ids) > domain.MaxOrgPerTenant {
		return fmt.Errorf("%w: ids must list every organization dashboard", shared.ErrValidation)
	}
	parsed := make([]shared.ID, 0, len(ids))
	seen := map[shared.ID]bool{}
	for _, raw := range ids {
		id, err := parseID(raw)
		if err != nil {
			return err
		}
		if seen[id] {
			return fmt.Errorf("%w: ids lists a dashboard twice", shared.ErrValidation)
		}
		seen[id] = true
		parsed = append(parsed, id)
	}
	if err := s.repo.Reorder(ctx, c.TenantID, parsed); err != nil {
		return err
	}
	s.logAudit(ctx, c, auditapp.NewSuccessEvent(auditdom.ActionDashboardOrgReordered, auditdom.ResourceTypeDashboard, c.TenantID.String()).
		WithMessage("Organization dashboards reordered").
		WithMetadata("order", ids))
	return nil
}

// SetOrgAudience replaces the audience of an organization dashboard: roles
// and teams of this organization. An empty audience means every
// dashboards:org:view holder. An audience narrows, it never widens: its
// members still need dashboards:org:view.
func (s *Service) SetOrgAudience(ctx context.Context, c Caller, id string, entries []domain.AudienceEntry) (*OrgDashboard, error) {
	d, err := s.managedOrg(ctx, c, id)
	if err != nil {
		return nil, err
	}
	if err := domain.ValidateAudience(entries); err != nil {
		return nil, err
	}
	before, err := s.repo.Audience(ctx, c.TenantID, d.ID())
	if err != nil {
		return nil, err
	}
	if err := s.repo.ReplaceAudience(ctx, c.TenantID, d.ID(), c.UserID, entries); err != nil {
		return nil, err
	}
	s.logAudit(ctx, c, s.orgEvent(auditdom.ActionDashboardAudienceChanged, d, "Organization dashboard audience changed").
		WithChanges(auditapp.DiffChanges(map[string]any{"audience": audienceKeys(before)}, map[string]any{"audience": audienceKeys(entries)})))
	return s.GetOrg(ctx, c, id)
}

// SetOrgSchedule sets the refresh schedule of an organization dashboard.
func (s *Service) SetOrgSchedule(ctx context.Context, c Caller, id string, in ScheduleInput) (*OrgDashboard, error) {
	d, err := s.managedOrg(ctx, c, id)
	if err != nil {
		return nil, err
	}
	sch, err := s.validSchedule(ctx, c.TenantID, in)
	if err != nil {
		return nil, err
	}
	if err := s.repo.SetSchedule(ctx, c.TenantID, shared.ID{}, d.ID(), sch, sch.Next(s.now())); err != nil {
		return nil, err
	}
	s.logAudit(ctx, c, s.orgEvent(auditdom.ActionDashboardScheduleChanged, d, "Organization dashboard refresh schedule changed").
		WithChanges(auditapp.DiffChanges(
			map[string]any{"refresh_schedule": string(d.Schedule().Interval), "refresh_daily_minute": d.Schedule().DailyMinute},
			map[string]any{"refresh_schedule": string(sch.Interval), "refresh_daily_minute": sch.DailyMinute})))
	return s.GetOrg(ctx, c, id)
}

// DuplicateOrg copies the layout of an organization dashboard the caller may
// see into a new personal dashboard of theirs (origin "duplicated"). The
// copy is computed for the caller's own data scope: organization numbers do
// not travel with it.
func (s *Service) DuplicateOrg(ctx context.Context, c Caller, id string) (*domain.Dashboard, error) {
	src, err := s.readableOrg(ctx, c, id)
	if err != nil {
		return nil, err
	}
	return s.copyTo(ctx, src, c.TenantID, c.UserID, domain.OriginDuplicated)
}

// ---------------------------------------------------------------------------
// Organization defaults
// ---------------------------------------------------------------------------

// Settings are the organization's dashboard defaults with the floor that
// bounds them.
type Settings struct {
	DefaultInterval    domain.Interval
	DefaultDailyMinute *int
	FloorMinutes       int
}

// GetSettings returns the organization's dashboard defaults and its refresh
// floor. Any member may read them (the schedule picker needs them).
func (s *Service) GetSettings(ctx context.Context, c Caller) (*Settings, error) {
	if s.settings == nil {
		return nil, fmt.Errorf("dashboard settings are not configured")
	}
	ds, err := s.settings.GetDashboardSettings(ctx, c.TenantID.String())
	if err != nil {
		return nil, err
	}
	floor, err := s.RefreshFloor(ctx, c.TenantID)
	if err != nil {
		return nil, err
	}
	out := &Settings{DefaultInterval: domain.Interval(ds.DefaultRefreshSchedule), DefaultDailyMinute: ds.DefaultRefreshDailyMinute, FloorMinutes: int(floor / time.Minute)}
	if out.DefaultInterval == domain.IntervalDefault {
		out.DefaultInterval = domain.DefaultInterval
	}
	return out, nil
}

// UpdateSettings sets the organization default refresh schedule (owners and
// administrators; the route gates). It must be a concrete cadence within the
// floor.
func (s *Service) UpdateSettings(ctx context.Context, c Caller, in ScheduleInput) (*Settings, error) {
	if s.settings == nil {
		return nil, fmt.Errorf("dashboard settings are not configured")
	}
	if in.Interval == domain.IntervalDefault {
		return nil, fmt.Errorf("%w: the organization default needs a cadence (manual, 5m, 15m, 1h, 6h or daily)", shared.ErrValidation)
	}
	sch, err := s.validSchedule(ctx, c.TenantID, in)
	if err != nil {
		return nil, err
	}
	if _, err := s.settings.UpdateDashboardSettings(ctx, c.TenantID.String(), tenantdom.DashboardSettings{
		DefaultRefreshSchedule:    string(sch.Interval),
		DefaultRefreshDailyMinute: sch.DailyMinute,
	}, c.Audit); err != nil {
		return nil, err
	}
	return s.GetSettings(ctx, c)
}

// RefreshFloor is the organization's shortest allowed refresh cadence: the
// limit dashboard_refresh_floor_minutes when set and longer than the base
// floor, else the base floor. A limit that cannot be read refuses
// (fail-closed: a schedule is never saved below an unknown floor).
func (s *Service) RefreshFloor(ctx context.Context, tenantID shared.ID) (time.Duration, error) {
	if s.limits == nil {
		return domain.BaseRefreshFloor, nil
	}
	v, err := s.limits.Limit(ctx, tenantID, limits.DashboardRefreshFloorMinutes)
	if err != nil {
		return 0, fmt.Errorf("read the dashboard refresh floor: %w", err)
	}
	if v == limits.Unlimited {
		return domain.BaseRefreshFloor, nil
	}
	floor := time.Duration(v) * time.Minute
	if floor < domain.BaseRefreshFloor {
		floor = domain.BaseRefreshFloor
	}
	return floor, nil
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func (s *Service) validSchedule(ctx context.Context, tenantID shared.ID, in ScheduleInput) (domain.Schedule, error) {
	floor, err := s.RefreshFloor(ctx, tenantID)
	if err != nil {
		return domain.Schedule{}, err
	}
	return domain.NewSchedule(in.Interval, in.DailyMinute, floor)
}

// readableOrg loads an organization dashboard the caller may read:
// dashboards:org:view (or manage) and, for a viewer, its audience. Outside
// the audience it is not found.
func (s *Service) readableOrg(ctx context.Context, c Caller, id string) (*domain.Dashboard, error) {
	if err := c.requireUser(); err != nil {
		return nil, err
	}
	if !c.has(permission.DashboardsOrgView) && !c.has(permission.DashboardsOrgManage) {
		return nil, ErrForbidden
	}
	dID, err := parseID(id)
	if err != nil {
		return nil, err
	}
	d, err := s.repo.GetOrg(ctx, c.TenantID, dID)
	if err != nil {
		return nil, err
	}
	if c.has(permission.DashboardsOrgManage) {
		return d, nil
	}
	ok, err := s.repo.InAudience(ctx, c.TenantID, dID, c.UserID)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, shared.ErrNotFound
	}
	return d, nil
}

func (s *Service) managedOrg(ctx context.Context, c Caller, id string) (*domain.Dashboard, error) {
	if err := c.requireManager(); err != nil {
		return nil, err
	}
	dID, err := parseID(id)
	if err != nil {
		return nil, err
	}
	return s.repo.GetOrg(ctx, c.TenantID, dID)
}

// copyTo creates a personal copy of src's layout for userID, with a free
// name ("Name", "Name (2)", ...).
func (s *Service) copyTo(ctx context.Context, src *domain.Dashboard, tenantID, userID shared.ID, origin domain.Origin) (*domain.Dashboard, error) {
	if err := s.personalRoom(ctx, tenantID, userID); err != nil {
		return nil, err
	}
	existing, err := s.repo.ListByUser(ctx, tenantID, userID)
	if err != nil {
		return nil, err
	}
	taken := make(map[string]bool, len(existing))
	for _, d := range existing {
		taken[d.Name()] = true
	}
	name := freeName(src.Name(), taken)
	c, err := src.CopyFor(userID, name, origin)
	if err != nil {
		return nil, err
	}
	if err := s.repo.Create(ctx, c); err != nil {
		return nil, err
	}
	return c, nil
}

func (s *Service) personalRoom(ctx context.Context, tenantID, userID shared.ID) error {
	n, err := s.repo.CountByUser(ctx, tenantID, userID)
	if err != nil {
		return err
	}
	if n >= domain.MaxPersonalPerUser {
		return domain.ErrPersonalLimit
	}
	return nil
}

// freeName returns base, or base with the lowest " (n)" suffix not taken,
// trimmed to the name limit.
func freeName(base string, taken map[string]bool) string {
	if !taken[base] {
		return base
	}
	for i := 2; i <= domain.MaxPersonalPerUser+1; i++ {
		suffix := fmt.Sprintf(" (%d)", i)
		b := base
		if r := []rune(b); len(r)+len(suffix) > 100 {
			b = string(r[:100-len(suffix)])
		}
		if n := b + suffix; !taken[n] {
			return n
		}
	}
	return base
}

func (s *Service) orgEvent(action auditdom.Action, d *domain.Dashboard, msg string) auditapp.AuditEvent {
	return auditapp.NewSuccessEvent(action, auditdom.ResourceTypeDashboard, d.ID().String()).
		WithResourceName(d.Name()).
		WithMessage(msg).
		WithMetadata("kind", string(domain.KindOrganization))
}

func (s *Service) logAudit(ctx context.Context, c Caller, ev auditapp.AuditEvent) {
	if s.audit == nil {
		return
	}
	actx := c.Audit
	actx.TenantID = c.TenantID.String()
	if err := s.audit.LogEvent(ctx, actx, ev); err != nil {
		s.log.Warn("dashboard audit failed", "error", err)
	}
}

func audienceKeys(entries []domain.AudienceEntry) []string {
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, string(e.Type)+":"+e.ID.String())
	}
	return out
}

func (c Caller) requireUser() error {
	if c.TenantID.IsZero() || c.UserID.IsZero() {
		return fmt.Errorf("%w: dashboards need a signed-in user", shared.ErrForbidden)
	}
	return nil
}

func (c Caller) requireManager() error {
	if err := c.requireUser(); err != nil {
		return err
	}
	if !c.has(permission.DashboardsOrgManage) {
		return ErrForbidden
	}
	return nil
}

func parseID(id string) (shared.ID, error) {
	dID, err := shared.IDFromString(id)
	if err != nil {
		return shared.ID{}, fmt.Errorf("%w: invalid dashboard id", shared.ErrValidation)
	}
	return dID, nil
}

func parseScope(tenantID, userID string) (shared.ID, shared.ID, error) {
	tID, err := shared.IDFromString(tenantID)
	if err != nil {
		return shared.ID{}, shared.ID{}, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	uID, err := shared.IDFromString(userID)
	if err != nil {
		return shared.ID{}, shared.ID{}, fmt.Errorf("%w: invalid user id", shared.ErrValidation)
	}
	return tID, uID, nil
}
