package compliance

import (
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
)

// Assessment represents a tenant's assessment of a compliance control.
type Assessment struct {
	id            shared.ID
	tenantID      shared.ID
	frameworkID   shared.ID
	controlID     shared.ID
	status        ControlStatus
	priority      Priority
	owner         string
	notes         string
	evidenceType  EvidenceType
	evidenceIDs   []string
	evidenceCount int
	findingCount  int
	assessedBy    *shared.ID
	assessedAt    *time.Time
	dueDate       *time.Time
	createdAt     time.Time
	updatedAt     time.Time
}

// ReconstituteAssessment creates an Assessment from persisted data.
func ReconstituteAssessment(
	id, tenantID, frameworkID, controlID shared.ID,
	status ControlStatus, priority Priority, owner, notes string,
	evidenceType EvidenceType, evidenceIDs []string, evidenceCount, findingCount int,
	assessedBy *shared.ID, assessedAt, dueDate *time.Time,
	createdAt, updatedAt time.Time,
) *Assessment {
	return &Assessment{
		id: id, tenantID: tenantID, frameworkID: frameworkID, controlID: controlID,
		status: status, priority: priority, owner: owner, notes: notes,
		evidenceType: evidenceType, evidenceIDs: evidenceIDs,
		evidenceCount: evidenceCount, findingCount: findingCount,
		assessedBy: assessedBy, assessedAt: assessedAt, dueDate: dueDate,
		createdAt: createdAt, updatedAt: updatedAt,
	}
}

// Getters
func (a *Assessment) ID() shared.ID            { return a.id }
func (a *Assessment) TenantID() shared.ID      { return a.tenantID }
func (a *Assessment) FrameworkID() shared.ID   { return a.frameworkID }
func (a *Assessment) ControlID() shared.ID     { return a.controlID }
func (a *Assessment) Status() ControlStatus    { return a.status }
func (a *Assessment) Priority() Priority       { return a.priority }
func (a *Assessment) Owner() string            { return a.owner }
func (a *Assessment) Notes() string            { return a.notes }
func (a *Assessment) EvidenceType() EvidenceType { return a.evidenceType }
func (a *Assessment) EvidenceIDs() []string    { return a.evidenceIDs }
func (a *Assessment) EvidenceCount() int       { return a.evidenceCount }
func (a *Assessment) FindingCount() int        { return a.findingCount }
func (a *Assessment) AssessedBy() *shared.ID   { return a.assessedBy }
func (a *Assessment) AssessedAt() *time.Time   { return a.assessedAt }
func (a *Assessment) DueDate() *time.Time      { return a.dueDate }
func (a *Assessment) CreatedAt() time.Time     { return a.createdAt }
func (a *Assessment) UpdatedAt() time.Time     { return a.updatedAt }

// UpdateStatus updates the assessment status.
func (a *Assessment) UpdateStatus(status ControlStatus, notes string, assessedBy shared.ID) {
	a.status = status
	a.notes = notes
	a.assessedBy = &assessedBy
	now := time.Now()
	a.assessedAt = &now
	a.updatedAt = now
}

// SetPriority sets assessment priority.
func (a *Assessment) SetPriority(priority Priority) {
	a.priority = priority
	a.updatedAt = time.Now()
}

// SetOwner sets assessment owner.
func (a *Assessment) SetOwner(owner string) {
	a.owner = owner
	a.updatedAt = time.Now()
}

// SetDueDate sets assessment due date.
func (a *Assessment) SetDueDate(dueDate *time.Time) {
	a.dueDate = dueDate
	a.updatedAt = time.Now()
}
