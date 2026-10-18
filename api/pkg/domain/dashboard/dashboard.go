// Package dashboard provides domain models for customizable dashboards
// (docs/architecture/dashboards.md, docs/rfcs/RFC-021-customizable-dashboards.md).
//
// A dashboard is a name plus a JSON widget layout, of one of two kinds:
//   - personal: owned by one (tenant, user), seen and changed only by its owner,
//     computed for the owner's own data scope;
//   - organization: owned by the organization (no user), seen by holders of
//     dashboards:org:view (optionally narrowed to an audience of roles or
//     teams) and changed only by holders of dashboards:org:manage.
//
// Every query is tenant-bound; personal queries also filter on the owner.
package dashboard

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

const (
	// maxNameLen bounds a dashboard name.
	maxNameLen = 100
	// maxDescriptionLen bounds a dashboard's free-text description.
	maxDescriptionLen = 500
	// maxWidgets bounds how many tiles one dashboard may hold (DoS-safe).
	maxWidgets = 40
	// maxWidgetConfigBytes bounds one widget's serialized config.
	maxWidgetConfigBytes = 4096
	// maxWidgetTypeLen bounds a widget type identifier.
	maxWidgetTypeLen = 64
	// maxCoord bounds each grid coordinate/size (DoS-safe: prevents an
	// absurd layout from being persisted).
	maxCoord = 1000
	// minColumns / maxColumns bound the column-count layout structure.
	minColumns = 1
	maxColumns = 4
	// defaultColumns is the column count applied when none is given.
	defaultColumns = 2
)

// Widget is one placed tile on a dashboard grid. Coordinates and sizes are
// grid units, bounded to keep a stored layout sane.
type Widget struct {
	WidgetType string         `json:"widget_type"`
	X          int            `json:"x"`
	Y          int            `json:"y"`
	W          int            `json:"w"`
	H          int            `json:"h"`
	Config     map[string]any `json:"config,omitempty"`
}

// Dashboard is a saved dashboard layout, personal or organization.
type Dashboard struct {
	id           shared.ID
	tenantID     shared.ID
	userID       shared.ID // zero for an organization dashboard
	kind         Kind
	name         string
	description  string
	columns      int
	isDefault    bool // the owner's default (personal only)
	isOrgDefault bool // the organization default (organization only)
	position     int
	schedule     Schedule
	origin       Origin
	widgets      []Widget
	createdAt    time.Time
	updatedAt    time.Time
}

// NewDashboard creates a validated Dashboard for the given (tenant, user).
func NewDashboard(tenantID, userID shared.ID, name, description string, columns int, widgets []Widget) (*Dashboard, error) {
	name = strings.TrimSpace(name)
	description = strings.TrimSpace(description)
	if columns == 0 {
		columns = defaultColumns
	}
	if err := validate(name, description, columns, widgets); err != nil {
		return nil, err
	}
	if widgets == nil {
		widgets = make([]Widget, 0)
	}
	now := time.Now().UTC()
	return &Dashboard{
		id:          shared.NewID(),
		tenantID:    tenantID,
		userID:      userID,
		kind:        KindPersonal,
		origin:      OriginUser,
		name:        name,
		description: description,
		columns:     columns,
		widgets:     widgets,
		createdAt:   now,
		updatedAt:   now,
	}, nil
}

// NewOrgDashboard creates a validated organization dashboard: it belongs to
// the organization, not to the person who created it.
func NewOrgDashboard(tenantID shared.ID, name, description string, columns int, widgets []Widget) (*Dashboard, error) {
	d, err := NewDashboard(tenantID, shared.ID{}, name, description, columns, widgets)
	if err != nil {
		return nil, err
	}
	d.kind = KindOrganization
	return d, nil
}

// CopyFor returns a personal copy of d's layout for userID: name,
// description, columns and widgets only. Nothing else (kind, audience,
// schedule, default) is copied, and no data travels with a layout.
func (d *Dashboard) CopyFor(userID shared.ID, name string, origin Origin) (*Dashboard, error) {
	widgets := make([]Widget, len(d.widgets))
	copy(widgets, d.widgets)
	c, err := NewDashboard(d.tenantID, userID, name, d.description, d.columns, widgets)
	if err != nil {
		return nil, err
	}
	c.origin = origin
	return c, nil
}

// Stored is a dashboard row as persisted.
type Stored struct {
	ID, TenantID, UserID shared.ID
	Kind                 Kind
	Name, Description    string
	Columns              int
	IsDefault            bool
	IsOrgDefault         bool
	Position             int
	Schedule             Schedule
	Origin               Origin
	Widgets              []Widget
	CreatedAt, UpdatedAt time.Time
}

// Reconstruct rebuilds a Dashboard from persistence without re-validating.
func Reconstruct(s Stored) *Dashboard {
	if s.Widgets == nil {
		s.Widgets = make([]Widget, 0)
	}
	if s.Columns == 0 {
		s.Columns = defaultColumns
	}
	if s.Kind == "" {
		s.Kind = KindPersonal
	}
	if s.Origin == "" {
		s.Origin = OriginUser
	}
	return &Dashboard{
		id:           s.ID,
		tenantID:     s.TenantID,
		userID:       s.UserID,
		kind:         s.Kind,
		name:         s.Name,
		description:  s.Description,
		columns:      s.Columns,
		isDefault:    s.IsDefault,
		isOrgDefault: s.IsOrgDefault,
		position:     s.Position,
		schedule:     s.Schedule,
		origin:       s.Origin,
		widgets:      s.Widgets,
		createdAt:    s.CreatedAt,
		updatedAt:    s.UpdatedAt,
	}
}

// Update replaces the name, description, columns and widget layout after
// validation.
func (d *Dashboard) Update(name, description string, columns int, widgets []Widget) error {
	name = strings.TrimSpace(name)
	description = strings.TrimSpace(description)
	if columns == 0 {
		columns = defaultColumns
	}
	if err := validate(name, description, columns, widgets); err != nil {
		return err
	}
	if widgets == nil {
		widgets = make([]Widget, 0)
	}
	d.name = name
	d.description = description
	d.columns = columns
	d.widgets = widgets
	d.updatedAt = time.Now().UTC()
	return nil
}

// validate enforces the invariants shared by NewDashboard and Update.
func validate(name, description string, columns int, widgets []Widget) error {
	if len(name) < 1 {
		return fmt.Errorf("%w: name is required", shared.ErrValidation)
	}
	if len(name) > maxNameLen {
		return fmt.Errorf("%w: name must be at most %d characters", shared.ErrValidation, maxNameLen)
	}
	if len(description) > maxDescriptionLen {
		return fmt.Errorf("%w: description must be at most %d characters", shared.ErrValidation, maxDescriptionLen)
	}
	if columns < minColumns || columns > maxColumns {
		return fmt.Errorf("%w: columns must be within %d..%d", shared.ErrValidation, minColumns, maxColumns)
	}
	if len(widgets) > maxWidgets {
		return fmt.Errorf("%w: at most %d widgets allowed", shared.ErrValidation, maxWidgets)
	}
	for i, wdg := range widgets {
		wt := strings.TrimSpace(wdg.WidgetType)
		if wt == "" {
			return fmt.Errorf("%w: widget[%d] widget_type is required", shared.ErrValidation, i)
		}
		if len(wt) > maxWidgetTypeLen {
			return fmt.Errorf("%w: widget[%d] widget_type must be at most %d characters", shared.ErrValidation, i, maxWidgetTypeLen)
		}
		if !inBounds(wdg.X) || !inBounds(wdg.Y) || !inBounds(wdg.W) || !inBounds(wdg.H) {
			return fmt.Errorf("%w: widget[%d] x/y/w/h must be within 0..%d", shared.ErrValidation, i, maxCoord)
		}
		if len(wdg.Config) > 0 {
			raw, err := json.Marshal(wdg.Config)
			if err != nil || len(raw) > maxWidgetConfigBytes {
				return fmt.Errorf("%w: widget[%d] config must be at most %d bytes", shared.ErrValidation, i, maxWidgetConfigBytes)
			}
		}
	}
	return nil
}

func inBounds(v int) bool { return v >= 0 && v <= maxCoord }

// Accessors.

func (d *Dashboard) ID() shared.ID        { return d.id }
func (d *Dashboard) TenantID() shared.ID  { return d.tenantID }
func (d *Dashboard) UserID() shared.ID    { return d.userID }
func (d *Dashboard) Kind() Kind           { return d.kind }
func (d *Dashboard) IsOrgDefault() bool   { return d.isOrgDefault }
func (d *Dashboard) Position() int        { return d.position }
func (d *Dashboard) Schedule() Schedule   { return d.schedule }
func (d *Dashboard) Origin() Origin       { return d.origin }
func (d *Dashboard) Name() string         { return d.name }
func (d *Dashboard) Description() string  { return d.description }
func (d *Dashboard) Columns() int         { return d.columns }
func (d *Dashboard) IsDefault() bool      { return d.isDefault }
func (d *Dashboard) Widgets() []Widget    { return d.widgets }
func (d *Dashboard) CreatedAt() time.Time { return d.createdAt }
func (d *Dashboard) UpdatedAt() time.Time { return d.updatedAt }

// Repository persists dashboards. Every method is tenant-bound; personal
// methods also filter on the owner, organization methods on kind.
type Repository interface {
	// Personal dashboards of (tenant, user).
	ListByUser(ctx context.Context, tenantID, userID shared.ID) ([]*Dashboard, error)
	GetByID(ctx context.Context, tenantID, userID, id shared.ID) (*Dashboard, error)
	CountByUser(ctx context.Context, tenantID, userID shared.ID) (int, error)
	// Create persists a new dashboard of either kind.
	Create(ctx context.Context, d *Dashboard) error
	// Update writes name, description, columns and layout (either kind).
	Update(ctx context.Context, d *Dashboard) error
	Delete(ctx context.Context, tenantID, userID, id shared.ID) error
	// SetDefault clears any other default for the user and marks id as the
	// single default, atomically. Returns shared.ErrNotFound if id is absent.
	SetDefault(ctx context.Context, tenantID, userID, id shared.ID) error
	// SetSchedule writes the refresh schedule of one dashboard (either kind:
	// userID zero means an organization dashboard).
	SetSchedule(ctx context.Context, tenantID, userID, id shared.ID, s Schedule, nextRefreshAt *time.Time) error

	// Organization dashboards of the tenant.
	ListOrg(ctx context.Context, tenantID shared.ID) ([]*Dashboard, error)
	// ListOrgVisible lists the organization dashboards whose audience lets
	// userID in (no audience, or one of the user's roles or active teams).
	ListOrgVisible(ctx context.Context, tenantID, userID shared.ID) ([]*Dashboard, error)
	GetOrg(ctx context.Context, tenantID, id shared.ID) (*Dashboard, error)
	// InAudience reports whether userID may see organization dashboard id
	// by its audience (true when it has none).
	InAudience(ctx context.Context, tenantID, id, userID shared.ID) (bool, error)
	CountOrg(ctx context.Context, tenantID shared.ID) (int, error)
	DeleteOrg(ctx context.Context, tenantID, id shared.ID) error
	SetOrgDefault(ctx context.Context, tenantID, id shared.ID) error
	// Reorder sets position = index for the given ids, which must be every
	// organization dashboard of the tenant exactly once.
	Reorder(ctx context.Context, tenantID shared.ID, ids []shared.ID) error
	Audience(ctx context.Context, tenantID, id shared.ID) ([]AudienceEntry, error)
	// ReplaceAudience validates that every principal belongs to the tenant
	// (a system role or one of its roles, one of its teams) and replaces the
	// audience atomically.
	ReplaceAudience(ctx context.Context, tenantID, id, actorID shared.ID, entries []AudienceEntry) error
}
