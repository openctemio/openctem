package compliance

import (
	"context"
	"fmt"

	"time"

	compliancedom "github.com/openctemio/api/pkg/domain/compliance"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
)

// ComplianceService handles compliance framework business operations.
type ComplianceService struct {
	frameworkRepo  compliancedom.FrameworkRepository
	controlRepo    compliancedom.ControlRepository
	assessmentRepo compliancedom.AssessmentRepository
	mappingRepo    compliancedom.MappingRepository
	findingRepo    vulnerability.FindingRepository // For draft guard on mapping
	logger         *logger.Logger
}

// NewComplianceService creates a new ComplianceService.
func NewComplianceService(
	frameworkRepo compliancedom.FrameworkRepository,
	controlRepo compliancedom.ControlRepository,
	assessmentRepo compliancedom.AssessmentRepository,
	mappingRepo compliancedom.MappingRepository,
	log *logger.Logger,
) *ComplianceService {
	return &ComplianceService{
		frameworkRepo:  frameworkRepo,
		controlRepo:    controlRepo,
		assessmentRepo: assessmentRepo,
		mappingRepo:    mappingRepo,
		logger:         log.With("service", "compliance"),
	}
}

// SetFindingRepository sets the finding repository for draft guard on compliance mapping.
func (s *ComplianceService) SetFindingRepository(repo vulnerability.FindingRepository) {
	s.findingRepo = repo
}

// =============================================
// FRAMEWORK OPERATIONS
// =============================================

// ListFrameworks lists compliance frameworks.
func (s *ComplianceService) ListFrameworks(ctx context.Context, tenantID string, page pagination.Pagination) (pagination.Result[*compliancedom.Framework], error) {
	tid, _ := shared.IDFromString(tenantID)
	filter := compliancedom.FrameworkFilter{TenantID: &tid}
	return s.frameworkRepo.List(ctx, filter, page)
}

// GetFramework retrieves a framework by ID with tenant isolation.
func (s *ComplianceService) GetFramework(ctx context.Context, tenantID, id string) (*compliancedom.Framework, error) {
	tid, _ := shared.IDFromString(tenantID)
	fid, _ := shared.IDFromString(id)
	return s.frameworkRepo.GetByID(ctx, tid, fid)
}

// GetFrameworkBySlug retrieves a system framework by slug.
func (s *ComplianceService) GetFrameworkBySlug(ctx context.Context, slug string) (*compliancedom.Framework, error) {
	return s.frameworkRepo.GetBySlug(ctx, slug)
}

// GetFrameworkStats returns compliance statistics for a framework.
func (s *ComplianceService) GetFrameworkStats(ctx context.Context, tenantID, frameworkID string) (*compliancedom.FrameworkStats, error) {
	tid, _ := shared.IDFromString(tenantID)
	fid, _ := shared.IDFromString(frameworkID)
	return s.assessmentRepo.GetStatsByFramework(ctx, tid, fid)
}

// =============================================
// CONTROL OPERATIONS
// =============================================

// ListControls lists controls for a framework with tenant verification.
func (s *ComplianceService) ListControls(ctx context.Context, tenantID, frameworkID string, page pagination.Pagination) (pagination.Result[*compliancedom.Control], error) {
	tid, _ := shared.IDFromString(tenantID)
	fid, _ := shared.IDFromString(frameworkID)
	// Verify tenant can access this framework
	if _, err := s.frameworkRepo.GetByID(ctx, tid, fid); err != nil {
		return pagination.Result[*compliancedom.Control]{}, err
	}
	return s.controlRepo.ListByFramework(ctx, fid, page)
}

// GetControl retrieves a control by ID and verifies its framework is accessible to the tenant.
func (s *ComplianceService) GetControl(ctx context.Context, tenantID, id string) (*compliancedom.Control, error) {
	tid, _ := shared.IDFromString(tenantID)
	cid, _ := shared.IDFromString(id)
	control, err := s.controlRepo.GetByID(ctx, cid)
	if err != nil {
		return nil, err
	}
	// Verify the control's framework is accessible to this tenant
	if _, err := s.frameworkRepo.GetByID(ctx, tid, control.FrameworkID()); err != nil {
		return nil, compliancedom.ErrControlNotFound
	}
	return control, nil
}

// =============================================
// ASSESSMENT OPERATIONS
// =============================================

// UpdateAssessmentInput contains input for updating an assessment.
type UpdateAssessmentInput struct {
	TenantID    string
	FrameworkID string
	ControlID   string
	Status      string
	Priority    string
	Owner       string
	Notes       string
	DueDate     *string
	ActorID     string
}

// UpdateAssessment creates or updates a control assessment.
func (s *ComplianceService) UpdateAssessment(ctx context.Context, input UpdateAssessmentInput) (*compliancedom.Assessment, error) {
	tenantID, _ := shared.IDFromString(input.TenantID)
	frameworkID, _ := shared.IDFromString(input.FrameworkID)
	controlID, _ := shared.IDFromString(input.ControlID)
	actorID, _ := shared.IDFromString(input.ActorID)

	status, err := compliancedom.ParseControlStatus(input.Status)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", shared.ErrValidation, err)
	}

	// Security: Verify tenant owns/can access the framework
	if _, err := s.frameworkRepo.GetByID(ctx, tenantID, frameworkID); err != nil {
		return nil, fmt.Errorf("%w: framework not accessible", shared.ErrValidation)
	}

	// Security: Verify control belongs to the specified framework
	control, err := s.controlRepo.GetByID(ctx, controlID)
	if err != nil {
		return nil, fmt.Errorf("%w: control not found", shared.ErrValidation)
	}
	if control.FrameworkID() != frameworkID {
		return nil, fmt.Errorf("%w: control does not belong to framework", shared.ErrValidation)
	}

	// Try to get existing assessment
	assessment, err := s.assessmentRepo.GetByTenantAndControl(ctx, tenantID, controlID)
	if err != nil {
		// Create new assessment
		assessment = compliancedom.ReconstituteAssessment(
			shared.NewID(), tenantID, frameworkID, controlID,
			compliancedom.ControlStatusNotAssessed, "", "", "",
			"", nil, 0, 0, nil, nil, nil,
			time.Now(), time.Now(),
		)
	}

	assessment.UpdateStatus(status, input.Notes, actorID)

	if input.Priority != "" {
		priority, _ := compliancedom.ParsePriority(input.Priority)
		assessment.SetPriority(priority)
	}
	if input.Owner != "" {
		assessment.SetOwner(input.Owner)
	}
	if input.DueDate != nil {
		assessment.SetDueDate(parseOptionalDate(input.DueDate))
	}

	if err := s.assessmentRepo.Upsert(ctx, assessment); err != nil {
		return nil, fmt.Errorf("failed to update assessment: %w", err)
	}

	s.logger.Info("assessment updated", "control_id", input.ControlID, "status", input.Status)
	return assessment, nil
}

// ListAssessments lists assessments for a framework.
func (s *ComplianceService) ListAssessments(ctx context.Context, tenantID, frameworkID string, page pagination.Pagination) (pagination.Result[*compliancedom.Assessment], error) {
	tid, _ := shared.IDFromString(tenantID)
	fid, _ := shared.IDFromString(frameworkID)
	return s.assessmentRepo.ListByFramework(ctx, tid, fid, page)
}

// GetComplianceStats returns overall compliance statistics.
func (s *ComplianceService) GetComplianceStats(ctx context.Context, tenantID string) (*ComplianceStatsResponse, error) {
	tid, _ := shared.IDFromString(tenantID)

	// Get all frameworks
	frameworks, err := s.frameworkRepo.List(ctx, compliancedom.FrameworkFilter{TenantID: &tid}, pagination.New(1, 100))
	if err != nil {
		return nil, err
	}

	overdue, _ := s.assessmentRepo.GetOverdueCount(ctx, tid)

	totalControls := 0
	for _, f := range frameworks.Data {
		totalControls += f.TotalControls()
	}

	return &ComplianceStatsResponse{
		TotalFrameworks: len(frameworks.Data),
		TotalControls:   totalControls,
		OverdueControls: int(overdue),
	}, nil
}

// ComplianceStatsResponse contains overall compliance stats.
type ComplianceStatsResponse struct {
	TotalFrameworks int `json:"total_frameworks"`
	TotalControls   int `json:"total_controls"`
	OverdueControls int `json:"overdue_controls"`
}

// =============================================
// MAPPING OPERATIONS
// =============================================

// MapFindingToControl maps a finding to a compliance control.
func (s *ComplianceService) MapFindingToControl(ctx context.Context, tenantID, findingID, controlID, actorID string, impact string) (*compliancedom.FindingControlMapping, error) {
	tid, _ := shared.IDFromString(tenantID)
	fid, _ := shared.IDFromString(findingID)
	cid, _ := shared.IDFromString(controlID)

	// Block mapping for draft/in_review findings (unconfirmed)
	if s.findingRepo != nil {
		finding, err := s.findingRepo.GetByID(ctx, tid, fid)
		if err != nil {
			return nil, fmt.Errorf("%w: finding not found", shared.ErrNotFound)
		}
		if finding.Status() == vulnerability.FindingStatusDraft || finding.Status() == vulnerability.FindingStatusInReview {
			return nil, fmt.Errorf("%w: cannot map unconfirmed findings to compliance controls", shared.ErrValidation)
		}
	}

	impactType := compliancedom.ImpactDirect
	if impact != "" {
		impactType = compliancedom.ImpactType(impact)
	}

	mapping := compliancedom.NewFindingControlMapping(tid, fid, cid, impactType)

	if err := s.mappingRepo.Create(ctx, mapping); err != nil {
		return nil, err
	}

	s.logger.Info("finding mapped to control", "finding_id", findingID, "control_id", controlID)
	return mapping, nil
}

// UnmapFindingFromControl removes a mapping.
func (s *ComplianceService) UnmapFindingFromControl(ctx context.Context, tenantID, mappingID string) error {
	tid, _ := shared.IDFromString(tenantID)
	mid, _ := shared.IDFromString(mappingID)
	return s.mappingRepo.Delete(ctx, tid, mid)
}

// GetFindingControls lists controls mapped to a finding.
func (s *ComplianceService) GetFindingControls(ctx context.Context, tenantID, findingID string) ([]*compliancedom.FindingControlMapping, error) {
	tid, _ := shared.IDFromString(tenantID)
	fid, _ := shared.IDFromString(findingID)
	return s.mappingRepo.ListByFinding(ctx, tid, fid)
}

// GetControlFindings lists findings mapped to a control.
func (s *ComplianceService) GetControlFindings(ctx context.Context, tenantID, controlID string) ([]*compliancedom.FindingControlMapping, error) {
	tid, _ := shared.IDFromString(tenantID)
	cid, _ := shared.IDFromString(controlID)
	return s.mappingRepo.ListByControl(ctx, tid, cid)
}


// parseOptionalDate parses an optional date string. Kept here (not
// exported) so compliance/ has no dependency on pentest_service.go
// which remained in package app due to cross-service deps.
func parseOptionalDate(s *string) *time.Time {
	if s == nil || *s == "" {
		return nil
	}
	t, err := time.Parse("2006-01-02", *s)
	if err != nil {
		return nil
	}
	return &t
}
