package compliance

import (
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
)

// Control represents an individual requirement within a compliance framework.
type Control struct {
	id              shared.ID
	frameworkID     shared.ID
	controlID       string // e.g., "CC6.1", "A.8.1"
	title           string
	description     string
	category        string
	parentControlID *shared.ID
	sortOrder       int
	metadata        map[string]any
	createdAt       time.Time
}

// ReconstituteControl creates a Control from persisted data.
func ReconstituteControl(
	id, frameworkID shared.ID, controlID, title, description, category string,
	parentControlID *shared.ID, sortOrder int, metadata map[string]any, createdAt time.Time,
) *Control {
	return &Control{
		id: id, frameworkID: frameworkID, controlID: controlID,
		title: title, description: description, category: category,
		parentControlID: parentControlID, sortOrder: sortOrder,
		metadata: metadata, createdAt: createdAt,
	}
}

// Getters
func (c *Control) ID() shared.ID              { return c.id }
func (c *Control) FrameworkID() shared.ID      { return c.frameworkID }
func (c *Control) ControlID() string          { return c.controlID }
func (c *Control) Title() string              { return c.title }
func (c *Control) Description() string        { return c.description }
func (c *Control) Category() string           { return c.category }
func (c *Control) ParentControlID() *shared.ID { return c.parentControlID }
func (c *Control) SortOrder() int             { return c.sortOrder }
func (c *Control) Metadata() map[string]any   { return c.metadata }
func (c *Control) CreatedAt() time.Time       { return c.createdAt }
