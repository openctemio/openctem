// Package compensatingcontrol provides public types and helpers reusable across the codebase.
package compensatingcontrol

import (
	"fmt"
	"slices"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
)

// ControlType represents the category of compensating control.
type ControlType string

const (
	ControlTypeSegmentation ControlType = "segmentation"
	ControlTypeIdentity     ControlType = "identity"
	ControlTypeRuntime      ControlType = "runtime"
	ControlTypeDetection    ControlType = "detection"
	ControlTypeOther        ControlType = "other"
)

// AllControlTypes returns every valid control type.
//
// This set is the single source of truth for the vocabulary and mirrors the
// compensating_controls_control_type_check CHECK constraint exactly. Anything
// outside it reaches Postgres as a constraint violation, which surfaces to the
// caller as a 500 instead of a 400 — so validate against this list before
// writing.
func AllControlTypes() []ControlType {
	return []ControlType{
		ControlTypeSegmentation,
		ControlTypeIdentity,
		ControlTypeRuntime,
		ControlTypeDetection,
		ControlTypeOther,
	}
}

// IsValid reports whether t is a control type the database will accept.
func (t ControlType) IsValid() bool {
	return slices.Contains(AllControlTypes(), t)
}

// ControlStatus represents the lifecycle status of a control.
type ControlStatus string

const (
	ControlStatusActive   ControlStatus = "active"
	ControlStatusInactive ControlStatus = "inactive"
	ControlStatusExpired  ControlStatus = "expired"
	ControlStatusUntested ControlStatus = "untested"
)

// AllControlStatuses returns every valid lifecycle status. Mirrors the
// compensating_controls_status_check CHECK constraint.
func AllControlStatuses() []ControlStatus {
	return []ControlStatus{
		ControlStatusActive,
		ControlStatusInactive,
		ControlStatusExpired,
		ControlStatusUntested,
	}
}

// IsValid reports whether s is a status the database will accept.
func (s ControlStatus) IsValid() bool {
	return slices.Contains(AllControlStatuses(), s)
}

// TestResult represents the outcome of a control effectiveness test.
type TestResult string

const (
	TestResultPass    TestResult = "pass"
	TestResultFail    TestResult = "fail"
	TestResultPartial TestResult = "partial"
)

// AllTestResults returns every valid test outcome. Mirrors the
// compensating_controls_test_result_check CHECK constraint.
func AllTestResults() []TestResult {
	return []TestResult{TestResultPass, TestResultFail, TestResultPartial}
}

// IsValid reports whether r is a test result the database will accept.
func (r TestResult) IsValid() bool {
	return slices.Contains(AllTestResults(), r)
}

// CompensatingControl represents a security control that mitigates risk
// without fixing the underlying vulnerability.
type CompensatingControl struct {
	id              shared.ID
	tenantID        shared.ID
	name            string
	description     string
	controlType     ControlType
	status          ControlStatus
	reductionFactor float64 // 0.0-1.0
	lastTestedAt    *time.Time
	testResult      *TestResult
	testEvidence    string
	expiresAt       *time.Time
	createdBy       *shared.ID
	createdAt       time.Time
	updatedAt       time.Time
}

// CompensatingControlData is the persistence representation.
type CompensatingControlData struct {
	ID              shared.ID
	TenantID        shared.ID
	Name            string
	Description     string
	ControlType     ControlType
	Status          ControlStatus
	ReductionFactor float64
	LastTestedAt    *time.Time
	TestResult      *TestResult
	TestEvidence    string
	ExpiresAt       *time.Time
	CreatedBy       *shared.ID
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// NewCompensatingControl creates a new control.
func NewCompensatingControl(
	tenantID shared.ID,
	name string,
	controlType ControlType,
	reductionFactor float64,
	createdBy shared.ID,
) (*CompensatingControl, error) {
	if name == "" {
		return nil, fmt.Errorf("%w: name is required", shared.ErrValidation)
	}
	if reductionFactor < 0 || reductionFactor > 1 {
		return nil, fmt.Errorf("%w: reduction_factor must be 0.0-1.0", shared.ErrValidation)
	}

	now := time.Now()
	return &CompensatingControl{
		id:              shared.NewID(),
		tenantID:        tenantID,
		name:            name,
		controlType:     controlType,
		status:          ControlStatusActive,
		reductionFactor: reductionFactor,
		createdBy:       &createdBy,
		createdAt:       now,
		updatedAt:       now,
	}, nil
}

// ReconstituteCompensatingControl recreates from persistence.
func ReconstituteCompensatingControl(data CompensatingControlData) *CompensatingControl {
	return &CompensatingControl{
		id:              data.ID,
		tenantID:        data.TenantID,
		name:            data.Name,
		description:     data.Description,
		controlType:     data.ControlType,
		status:          data.Status,
		reductionFactor: data.ReductionFactor,
		lastTestedAt:    data.LastTestedAt,
		testResult:      data.TestResult,
		testEvidence:    data.TestEvidence,
		expiresAt:       data.ExpiresAt,
		createdBy:       data.CreatedBy,
		createdAt:       data.CreatedAt,
		updatedAt:       data.UpdatedAt,
	}
}

// Getters
func (c *CompensatingControl) ID() shared.ID            { return c.id }
func (c *CompensatingControl) TenantID() shared.ID      { return c.tenantID }
func (c *CompensatingControl) Name() string              { return c.name }
func (c *CompensatingControl) Description() string       { return c.description }
func (c *CompensatingControl) ControlType() ControlType  { return c.controlType }
func (c *CompensatingControl) Status() ControlStatus     { return c.status }
func (c *CompensatingControl) ReductionFactor() float64  { return c.reductionFactor }
func (c *CompensatingControl) LastTestedAt() *time.Time  { return c.lastTestedAt }
func (c *CompensatingControl) TestResult() *TestResult   { return c.testResult }
func (c *CompensatingControl) TestEvidence() string      { return c.testEvidence }
func (c *CompensatingControl) ExpiresAt() *time.Time     { return c.expiresAt }
func (c *CompensatingControl) CreatedAt() time.Time      { return c.createdAt }

// IsEffective returns true if the control is active, tested successfully, and not expired.
func (c *CompensatingControl) IsEffective() bool {
	if c.status != ControlStatusActive {
		return false
	}
	if c.testResult != nil && *c.testResult == TestResultFail {
		return false
	}
	if c.expiresAt != nil && c.expiresAt.Before(time.Now()) {
		return false
	}
	return true
}

// RecordTest records the result of a control effectiveness test.
func (c *CompensatingControl) RecordTest(result TestResult, evidence string) {
	c.testResult = &result
	c.testEvidence = evidence
	now := time.Now()
	c.lastTestedAt = &now
	c.updatedAt = now

	// Auto-deactivate if test failed
	if result == TestResultFail {
		c.status = ControlStatusInactive
	}
}

// SetDescription updates the description.
func (c *CompensatingControl) SetDescription(desc string) {
	c.description = desc
	c.updatedAt = time.Now()
}

// SetReductionFactor updates the reduction factor.
func (c *CompensatingControl) SetReductionFactor(factor float64) error {
	if factor < 0 || factor > 1 {
		return fmt.Errorf("%w: reduction_factor must be 0.0-1.0", shared.ErrValidation)
	}
	c.reductionFactor = factor
	c.updatedAt = time.Now()
	return nil
}

// Activate marks the control as active.
func (c *CompensatingControl) Activate() {
	c.status = ControlStatusActive
	c.updatedAt = time.Now()
}

// Deactivate marks the control as inactive.
func (c *CompensatingControl) Deactivate() {
	c.status = ControlStatusInactive
	c.updatedAt = time.Now()
}
