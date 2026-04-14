package simulation

import (
	"fmt"
	"slices"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
)

// ControlTestStatus defines the test result status.
type ControlTestStatus string

const (
	ControlTestStatusUntested      ControlTestStatus = "untested"
	ControlTestStatusPass          ControlTestStatus = "pass"
	ControlTestStatusFail          ControlTestStatus = "fail"
	ControlTestStatusPartial       ControlTestStatus = "partial"
	ControlTestStatusNotApplicable ControlTestStatus = "not_applicable"
)

// ControlTest represents a security control effectiveness test.
type ControlTest struct {
	id                  shared.ID
	tenantID            shared.ID
	name                string
	description         string
	framework           string
	controlID           string
	controlName         string
	category            string
	testProcedure       string
	expectedResult      string
	status              ControlTestStatus
	lastTestedAt        *time.Time
	lastTestedBy        *shared.ID
	evidence            string
	notes               string
	riskLevel           string
	linkedSimulationIDs []string
	tags                []string
	createdAt           time.Time
	updatedAt           time.Time
}

// NewControlTest creates a new control test.
func NewControlTest(tenantID shared.ID, name, framework, controlID string) (*ControlTest, error) {
	if name == "" {
		return nil, fmt.Errorf("%w: name is required", shared.ErrValidation)
	}
	if framework == "" {
		return nil, fmt.Errorf("%w: framework is required", shared.ErrValidation)
	}
	now := time.Now()
	return &ControlTest{
		id:                  shared.NewID(),
		tenantID:            tenantID,
		name:                name,
		framework:           framework,
		controlID:           controlID,
		status:              ControlTestStatusUntested,
		riskLevel:           "medium",
		linkedSimulationIDs: []string{},
		tags:                []string{},
		createdAt:           now,
		updatedAt:           now,
	}, nil
}

// ReconstituteControlTest creates from persisted data.
func ReconstituteControlTest(
	id, tenantID shared.ID,
	name, description, framework, controlID, controlName, category string,
	testProcedure, expectedResult string,
	status ControlTestStatus,
	lastTestedAt *time.Time, lastTestedBy *shared.ID,
	evidence, notes, riskLevel string,
	linkedSimulationIDs, tags []string,
	createdAt, updatedAt time.Time,
) *ControlTest {
	return &ControlTest{
		id: id, tenantID: tenantID,
		name: name, description: description,
		framework: framework, controlID: controlID,
		controlName: controlName, category: category,
		testProcedure: testProcedure, expectedResult: expectedResult,
		status: status,
		lastTestedAt: lastTestedAt, lastTestedBy: lastTestedBy,
		evidence: evidence, notes: notes, riskLevel: riskLevel,
		linkedSimulationIDs: linkedSimulationIDs, tags: tags,
		createdAt: createdAt, updatedAt: updatedAt,
	}
}

// Getters
func (c *ControlTest) ID() shared.ID                 { return c.id }
func (c *ControlTest) TenantID() shared.ID            { return c.tenantID }
func (c *ControlTest) Name() string                   { return c.name }
func (c *ControlTest) Description() string             { return c.description }
func (c *ControlTest) Framework() string               { return c.framework }
func (c *ControlTest) ControlID() string               { return c.controlID }
func (c *ControlTest) ControlName() string             { return c.controlName }
func (c *ControlTest) Category() string                { return c.category }
func (c *ControlTest) TestProcedure() string           { return c.testProcedure }
func (c *ControlTest) ExpectedResult() string          { return c.expectedResult }
func (c *ControlTest) Status() ControlTestStatus       { return c.status }
func (c *ControlTest) LastTestedAt() *time.Time        { return c.lastTestedAt }
func (c *ControlTest) LastTestedBy() *shared.ID        { return c.lastTestedBy }
func (c *ControlTest) Evidence() string                { return c.evidence }
func (c *ControlTest) Notes() string                   { return c.notes }
func (c *ControlTest) RiskLevel() string               { return c.riskLevel }
func (c *ControlTest) LinkedSimulationIDs() []string   { return c.linkedSimulationIDs }
func (c *ControlTest) Tags() []string                  { return c.tags }
func (c *ControlTest) CreatedAt() time.Time            { return c.createdAt }
func (c *ControlTest) UpdatedAt() time.Time            { return c.updatedAt }

// Update sets mutable fields.
func (c *ControlTest) Update(name, description, controlName, category string) {
	if name != "" {
		c.name = name
	}
	c.description = description
	c.controlName = controlName
	c.category = category
	c.updatedAt = time.Now()
}

// SetTestDetails sets test procedure and expected result.
func (c *ControlTest) SetTestDetails(procedure, expected string) {
	c.testProcedure = procedure
	c.expectedResult = expected
	c.updatedAt = time.Now()
}

// RecordResult records a test result.
func (c *ControlTest) RecordResult(status ControlTestStatus, evidence, notes string, testedBy shared.ID) {
	now := time.Now()
	c.status = status
	c.evidence = evidence
	c.notes = notes
	c.lastTestedAt = &now
	c.lastTestedBy = &testedBy
	c.updatedAt = now
}

// LinkSimulation links a simulation to this control test.
func (c *ControlTest) LinkSimulation(simulationID string) {
	if slices.Contains(c.linkedSimulationIDs, simulationID) {
		return
	}
	c.linkedSimulationIDs = append(c.linkedSimulationIDs, simulationID)
	c.updatedAt = time.Now()
}
