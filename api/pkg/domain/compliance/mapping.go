package compliance

import (
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
)

// FindingControlMapping represents a link between a finding and a compliance control.
type FindingControlMapping struct {
	id        shared.ID
	tenantID  shared.ID
	findingID shared.ID
	controlID shared.ID
	impact    ImpactType
	notes     string
	createdAt time.Time
	createdBy *shared.ID
}

// NewFindingControlMapping creates a new mapping.
func NewFindingControlMapping(tenantID, findingID, controlID shared.ID, impact ImpactType) *FindingControlMapping {
	return &FindingControlMapping{
		id:        shared.NewID(),
		tenantID:  tenantID,
		findingID: findingID,
		controlID: controlID,
		impact:    impact,
		createdAt: time.Now(),
	}
}

// ReconstituteFindingControlMapping creates a mapping from persisted data.
func ReconstituteFindingControlMapping(
	id, tenantID, findingID, controlID shared.ID,
	impact ImpactType, notes string, createdAt time.Time, createdBy *shared.ID,
) *FindingControlMapping {
	return &FindingControlMapping{
		id: id, tenantID: tenantID, findingID: findingID, controlID: controlID,
		impact: impact, notes: notes, createdAt: createdAt, createdBy: createdBy,
	}
}

// Getters
func (m *FindingControlMapping) ID() shared.ID        { return m.id }
func (m *FindingControlMapping) TenantID() shared.ID  { return m.tenantID }
func (m *FindingControlMapping) FindingID() shared.ID { return m.findingID }
func (m *FindingControlMapping) ControlID() shared.ID { return m.controlID }
func (m *FindingControlMapping) Impact() ImpactType   { return m.impact }
func (m *FindingControlMapping) Notes() string        { return m.notes }
func (m *FindingControlMapping) CreatedAt() time.Time { return m.createdAt }
func (m *FindingControlMapping) CreatedBy() *shared.ID { return m.createdBy }
