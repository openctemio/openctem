// Package dashboard provides domain models for per-user customizable dashboards
// (RFC-021). A user owns 0..N saved dashboards, each a name plus a JSON widget
// layout. Everything is self-scoped: a dashboard always belongs to exactly one
// (tenant, user), and the persistence layer filters every query by both.
package dashboard

import (
	"context"
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
	maxWidgets = 50
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

// Dashboard is a user's saved dashboard layout.
type Dashboard struct {
	id          shared.ID
	tenantID    shared.ID
	userID      shared.ID
	name        string
	description string
	columns     int
	isDefault   bool
	widgets     []Widget
	createdAt   time.Time
	updatedAt   time.Time
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
		name:        name,
		description: description,
		columns:     columns,
		isDefault:   false,
		widgets:     widgets,
		createdAt:   now,
		updatedAt:   now,
	}, nil
}

// Reconstruct rebuilds a Dashboard from persistence without re-validating.
func Reconstruct(
	id, tenantID, userID shared.ID,
	name, description string,
	columns int,
	isDefault bool,
	widgets []Widget,
	createdAt, updatedAt time.Time,
) *Dashboard {
	if widgets == nil {
		widgets = make([]Widget, 0)
	}
	if columns == 0 {
		columns = defaultColumns
	}
	return &Dashboard{
		id:          id,
		tenantID:    tenantID,
		userID:      userID,
		name:        name,
		description: description,
		columns:     columns,
		isDefault:   isDefault,
		widgets:     widgets,
		createdAt:   createdAt,
		updatedAt:   updatedAt,
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
	}
	return nil
}

func inBounds(v int) bool { return v >= 0 && v <= maxCoord }

// Accessors.

func (d *Dashboard) ID() shared.ID        { return d.id }
func (d *Dashboard) TenantID() shared.ID  { return d.tenantID }
func (d *Dashboard) UserID() shared.ID    { return d.userID }
func (d *Dashboard) Name() string         { return d.name }
func (d *Dashboard) Description() string  { return d.description }
func (d *Dashboard) Columns() int         { return d.columns }
func (d *Dashboard) IsDefault() bool      { return d.isDefault }
func (d *Dashboard) Widgets() []Widget    { return d.widgets }
func (d *Dashboard) CreatedAt() time.Time { return d.createdAt }
func (d *Dashboard) UpdatedAt() time.Time { return d.updatedAt }

// Repository persists user dashboards. EVERY method is scoped by both
// tenant_id and user_id so a dashboard can never leak across users or tenants.
type Repository interface {
	ListByUser(ctx context.Context, tenantID, userID shared.ID) ([]*Dashboard, error)
	GetByID(ctx context.Context, tenantID, userID, id shared.ID) (*Dashboard, error)
	Create(ctx context.Context, d *Dashboard) error
	Update(ctx context.Context, d *Dashboard) error
	Delete(ctx context.Context, tenantID, userID, id shared.ID) error
	// SetDefault clears any other default for the user and marks id as the
	// single default, atomically. Returns shared.ErrNotFound if id is absent.
	SetDefault(ctx context.Context, tenantID, userID, id shared.ID) error
}
