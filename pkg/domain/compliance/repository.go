package compliance

import (
	"context"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/pagination"
)

// FrameworkFilter defines criteria for filtering frameworks.
type FrameworkFilter struct {
	TenantID *shared.ID
	Category *FrameworkCategory
	IsSystem *bool
	IsActive *bool
	Search   *string
}

// FrameworkRepository defines the interface for framework persistence.
type FrameworkRepository interface {
	Create(ctx context.Context, framework *Framework) error
	GetByID(ctx context.Context, tenantID, id shared.ID) (*Framework, error)
	GetBySlug(ctx context.Context, slug string) (*Framework, error)
	Update(ctx context.Context, framework *Framework) error
	Delete(ctx context.Context, id shared.ID) error
	List(ctx context.Context, filter FrameworkFilter, page pagination.Pagination) (pagination.Result[*Framework], error)
}

// ControlFilter defines criteria for filtering controls.
type ControlFilter struct {
	FrameworkID *shared.ID
	Category    *string
	ParentOnly  bool // Only top-level controls (parent_control_id IS NULL)
}

// ControlRepository defines the interface for control persistence.
type ControlRepository interface {
	Create(ctx context.Context, control *Control) error
	GetByID(ctx context.Context, id shared.ID) (*Control, error)
	ListByFramework(ctx context.Context, frameworkID shared.ID, page pagination.Pagination) (pagination.Result[*Control], error)
	CountByFramework(ctx context.Context, frameworkID shared.ID) (int64, error)
}

// AssessmentFilter defines criteria for filtering assessments.
type AssessmentFilter struct {
	TenantID    *shared.ID
	FrameworkID *shared.ID
	Status      *ControlStatus
	Priority    *Priority
}

// AssessmentRepository defines the interface for assessment persistence.
type AssessmentRepository interface {
	GetByTenantAndControl(ctx context.Context, tenantID, controlID shared.ID) (*Assessment, error)
	Upsert(ctx context.Context, assessment *Assessment) error
	ListByFramework(ctx context.Context, tenantID, frameworkID shared.ID, page pagination.Pagination) (pagination.Result[*Assessment], error)
	GetStatsByFramework(ctx context.Context, tenantID, frameworkID shared.ID) (*FrameworkStats, error)
	GetOverdueCount(ctx context.Context, tenantID shared.ID) (int64, error)
}

// FrameworkStats holds aggregated compliance statistics for a framework.
type FrameworkStats struct {
	TotalControls  int64
	Implemented    int64
	Partial        int64
	NotImplemented int64
	NotApplicable  int64
	NotAssessed    int64
}

// ComplianceScore calculates the compliance percentage.
func (s *FrameworkStats) ComplianceScore() float64 {
	assessable := s.TotalControls - s.NotApplicable
	if assessable == 0 {
		return 100.0
	}
	return float64(s.Implemented) / float64(assessable) * 100.0
}

// MappingRepository defines the interface for finding-to-control mapping persistence.
type MappingRepository interface {
	Create(ctx context.Context, mapping *FindingControlMapping) error
	Delete(ctx context.Context, tenantID, id shared.ID) error
	ListByFinding(ctx context.Context, tenantID, findingID shared.ID) ([]*FindingControlMapping, error)
	ListByControl(ctx context.Context, tenantID, controlID shared.ID) ([]*FindingControlMapping, error)
}
