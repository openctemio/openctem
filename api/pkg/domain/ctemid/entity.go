package ctemid

import (
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
)

// CTEMID is one entry in the CTEM-ID catalog.
type CTEMID struct {
	id          shared.ID
	ctemID      string
	category    Category
	title       string
	description string
	severity    string
	sourceURL   string
	publishedAt *time.Time
	raw         []byte
	createdAt   time.Time
	updatedAt   time.Time
}

// NewCTEMID creates a catalog entry. ctemID, category and title are required by
// the caller (the parser drops entries missing them); this constructor does not
// re-validate because the catalog is fail-open reference data.
func NewCTEMID(ctemID string, category Category, title, description, severity, sourceURL string, publishedAt *time.Time, raw []byte) *CTEMID {
	now := time.Now().UTC()
	return &CTEMID{
		id:          shared.NewID(),
		ctemID:      ctemID,
		category:    category,
		title:       title,
		description: description,
		severity:    severity,
		sourceURL:   sourceURL,
		publishedAt: publishedAt,
		raw:         raw,
		createdAt:   now,
		updatedAt:   now,
	}
}

// Reconstitute rebuilds a CTEMID from persistence.
func Reconstitute(id shared.ID, ctemID string, category Category, title, description, severity, sourceURL string, publishedAt *time.Time, raw []byte, createdAt, updatedAt time.Time) *CTEMID {
	return &CTEMID{
		id:          id,
		ctemID:      ctemID,
		category:    category,
		title:       title,
		description: description,
		severity:    severity,
		sourceURL:   sourceURL,
		publishedAt: publishedAt,
		raw:         raw,
		createdAt:   createdAt,
		updatedAt:   updatedAt,
	}
}

// ID returns the internal id.
func (c *CTEMID) ID() shared.ID { return c.id }

// CTEMID returns the external catalog identifier.
func (c *CTEMID) CTEMID() string { return c.ctemID }

// Category returns the exposure class.
func (c *CTEMID) Category() Category { return c.category }

// Title returns the title.
func (c *CTEMID) Title() string { return c.title }

// Description returns the description.
func (c *CTEMID) Description() string { return c.description }

// Severity returns the feed-provided severity (may be empty).
func (c *CTEMID) Severity() string { return c.severity }

// SourceURL returns the feed-provided source URL (may be empty).
func (c *CTEMID) SourceURL() string { return c.sourceURL }

// PublishedAt returns the feed-provided publish time (may be nil).
func (c *CTEMID) PublishedAt() *time.Time { return c.publishedAt }

// Raw returns the raw JSON of the feed entry.
func (c *CTEMID) Raw() []byte { return c.raw }

// CreatedAt returns the creation timestamp.
func (c *CTEMID) CreatedAt() time.Time { return c.createdAt }

// UpdatedAt returns the last update timestamp.
func (c *CTEMID) UpdatedAt() time.Time { return c.updatedAt }
