package unit

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/finding"
	lc "github.com/openctemio/openctem/api/pkg/domain/findinglifecycle"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/pagination"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Mock: ApprovalRepository
// =============================================================================

type mockApprovalRepository struct {
	approvals map[shared.ID]*vulnerability.Approval
	createErr error
	updateErr error
	findings  *mockFindingRepository
}

func newMockApprovalRepository() *mockApprovalRepository {
	return &mockApprovalRepository{
		approvals: make(map[shared.ID]*vulnerability.Approval),
	}
}

func (m *mockApprovalRepository) Create(_ context.Context, approval *vulnerability.Approval) error {
	if m.createErr != nil {
		return m.createErr
	}
	m.approvals[approval.ID] = approval
	return nil
}

func (m *mockApprovalRepository) GetByTenantAndID(_ context.Context, tenantID, id shared.ID) (*vulnerability.Approval, error) {
	a, ok := m.approvals[id]
	if !ok {
		return nil, shared.ErrNotFound
	}
	if a.TenantID != tenantID {
		return nil, shared.ErrNotFound
	}
	return a, nil
}

func (m *mockApprovalRepository) ListByFinding(_ context.Context, tenantID, findingID shared.ID) ([]*vulnerability.Approval, error) {
	result := make([]*vulnerability.Approval, 0)
	for _, a := range m.approvals {
		if a.TenantID == tenantID && a.FindingID == findingID {
			result = append(result, a)
		}
	}
	return result, nil
}

func (m *mockApprovalRepository) List(_ context.Context, tenantID shared.ID, filter vulnerability.ApprovalFilter, page pagination.Pagination, scope *shared.DataScope) (vulnerability.ApprovalPage, error) {
	counts := map[vulnerability.ApprovalStatus]int64{}
	result := make([]*vulnerability.Approval, 0)
	for _, a := range m.approvals {
		if a.TenantID != tenantID {
			continue
		}
		counts[a.Status]++
		if filter.Status == "" || a.Status == filter.Status {
			result = append(result, a)
		}
	}
	total := int64(len(result))

	start := (page.Page - 1) * page.PerPage
	if start > int(total) {
		start = int(total)
	}
	end := start + page.PerPage
	if end > int(total) {
		end = int(total)
	}

	return vulnerability.ApprovalPage{
		Result:       pagination.NewResult(result[start:end], total, page),
		StatusCounts: counts,
	}, nil
}

func (m *mockApprovalRepository) ListExpiredApproved(_ context.Context, limit int) ([]*vulnerability.Approval, error) {
	result := make([]*vulnerability.Approval, 0)
	for _, a := range m.approvals {
		if a.Status == vulnerability.ApprovalStatusApproved && a.IsExpired() {
			result = append(result, a)
			if len(result) >= limit {
				break
			}
		}
	}
	return result, nil
}

// ApproveAndApply applies the status through the linked finding mock (the
// database writes both in one transaction).
func (m *mockApprovalRepository) ApproveAndApply(ctx context.Context, approval *vulnerability.Approval, _ *vulnerability.FindingActivity) error {
	if m.updateErr != nil {
		return m.updateErr
	}
	if m.findings != nil {
		var err error
		status := vulnerability.FindingStatus(approval.RequestedStatus)
		if status == vulnerability.FindingStatusAccepted {
			err = m.findings.AcceptUntil(ctx, approval.TenantID, approval.FindingID, *approval.ExpiresAt, approval.ApprovedBy, approval.ClosureReason)
		} else {
			err = m.findings.UpdateStatusBatch(ctx, approval.TenantID, []shared.ID{approval.FindingID}, status, "", approval.ApprovedBy,
				vulnerability.Closure{Reason: approval.ClosureReason, Verification: vulnerability.VerificationSecurityReview})
		}
		if err != nil {
			return err
		}
	}
	m.approvals[approval.ID] = approval
	return nil
}

func (m *mockApprovalRepository) Update(_ context.Context, approval *vulnerability.Approval) error {
	if m.updateErr != nil {
		return m.updateErr
	}
	m.approvals[approval.ID] = approval
	return nil
}

// =============================================================================
// Mock: FindingRepository (minimal - only methods used by approval service)
// =============================================================================

type mockFindingRepository struct {
	findings       map[shared.ID]*vulnerability.Finding
	getByIDErr     error
	statusBatchErr error
	statusUpdates  []statusBatchCall
}

type statusBatchCall struct {
	TenantID   shared.ID
	IDs        []shared.ID
	Status     vulnerability.FindingStatus
	Resolution string
	ResolvedBy *shared.ID
	Closure    vulnerability.Closure
}

func newMockFindingRepository() *mockFindingRepository {
	return &mockFindingRepository{
		findings: make(map[shared.ID]*vulnerability.Finding),
	}
}

// Implement all FindingRepository methods with stubs.
// Only GetByID and UpdateStatusBatch have real logic since those are used by the approval service.

func (m *mockFindingRepository) Create(_ context.Context, _ *vulnerability.Finding) error {
	return nil
}
func (m *mockFindingRepository) CreateInTx(_ context.Context, _ *sql.Tx, _ *vulnerability.Finding) error {
	return nil
}
func (m *mockFindingRepository) CreateBatch(_ context.Context, _ []*vulnerability.Finding) error {
	return nil
}
func (m *mockFindingRepository) CreateBatchWithResult(_ context.Context, _ []*vulnerability.Finding) (*vulnerability.BatchCreateResult, error) {
	return nil, nil
}
func (m *mockFindingRepository) GetByID(_ context.Context, tenantID, id shared.ID) (*vulnerability.Finding, error) {
	if m.getByIDErr != nil {
		return nil, m.getByIDErr
	}
	f, ok := m.findings[id]
	if !ok {
		return nil, shared.ErrNotFound
	}
	return f, nil
}
func (m *mockFindingRepository) GetByIDs(_ context.Context, tenantID shared.ID, ids []shared.ID) ([]*vulnerability.Finding, error) {
	var out []*vulnerability.Finding
	for _, id := range ids {
		if f, ok := m.findings[id]; ok && f.TenantID() == tenantID {
			out = append(out, f)
		}
	}
	return out, nil
}
func (m *mockFindingRepository) Update(_ context.Context, _ *vulnerability.Finding) error {
	return nil
}
func (m *mockFindingRepository) Delete(_ context.Context, _, _ shared.ID) error {
	return nil
}
func (m *mockFindingRepository) List(_ context.Context, _ vulnerability.FindingFilter, _ vulnerability.FindingListOptions, _ pagination.Pagination) (pagination.Result[*vulnerability.Finding], error) {
	return pagination.Result[*vulnerability.Finding]{}, nil
}
func (m *mockFindingRepository) ListByAssetID(_ context.Context, _, _ shared.ID, _ vulnerability.FindingListOptions, _ pagination.Pagination) (pagination.Result[*vulnerability.Finding], error) {
	return pagination.Result[*vulnerability.Finding]{}, nil
}
func (m *mockFindingRepository) ListByVulnerabilityID(_ context.Context, _, _ shared.ID, _ vulnerability.FindingListOptions, _ pagination.Pagination) (pagination.Result[*vulnerability.Finding], error) {
	return pagination.Result[*vulnerability.Finding]{}, nil
}
func (m *mockFindingRepository) ListByComponentID(_ context.Context, _, _ shared.ID, _ vulnerability.FindingListOptions, _ pagination.Pagination) (pagination.Result[*vulnerability.Finding], error) {
	return pagination.Result[*vulnerability.Finding]{}, nil
}
func (m *mockFindingRepository) ListAffectedAssetsByVulnerabilityID(_ context.Context, _, _ shared.ID, _ bool, _ pagination.Pagination, _ *shared.DataScope) (pagination.Result[vulnerability.VulnerabilityAffectedAsset], error) {
	return pagination.Result[vulnerability.VulnerabilityAffectedAsset]{}, nil
}
func (m *mockFindingRepository) ListActiveCVEsByTenant(_ context.Context, _ shared.ID, _ vulnerability.ActiveCVEFilter, _ pagination.Pagination) (pagination.Result[vulnerability.ActiveCVE], error) {
	return pagination.Result[vulnerability.ActiveCVE]{}, nil
}
func (m *mockFindingRepository) GetActiveCVEStats(_ context.Context, _ shared.ID, _ bool, _ *shared.DataScope) (*vulnerability.ActiveCVEStats, error) {
	return &vulnerability.ActiveCVEStats{BySeverity: map[string]int{}}, nil
}
func (m *mockFindingRepository) Count(_ context.Context, _ vulnerability.FindingFilter) (int64, error) {
	return 0, nil
}
func (m *mockFindingRepository) CountByAssetID(_ context.Context, _, _ shared.ID) (int64, error) {
	return 0, nil
}
func (m *mockFindingRepository) CountOpenByAssetID(_ context.Context, _, _ shared.ID) (int64, error) {
	return 0, nil
}
func (m *mockFindingRepository) GetByFingerprint(_ context.Context, _ shared.ID, _ string) (*vulnerability.Finding, error) {
	return nil, nil
}
func (m *mockFindingRepository) ExistsByFingerprint(_ context.Context, _ shared.ID, _ string) (bool, error) {
	return false, nil
}
func (m *mockFindingRepository) CheckFingerprintsExist(_ context.Context, _ shared.ID, _ []string) (map[string]bool, error) {
	return nil, nil
}
func (m *mockFindingRepository) UpdateScanIDBatchByFingerprints(_ context.Context, _ shared.ID, _ []string, _, _ string) (int64, error) {
	return 0, nil
}
func (m *mockFindingRepository) UpdateSnippetBatchByFingerprints(_ context.Context, _ shared.ID, _ map[string]string) (int64, error) {
	return 0, nil
}
func (m *mockFindingRepository) BatchCountByAssetIDs(_ context.Context, _ shared.ID, _ []shared.ID) (map[shared.ID]int64, error) {
	return nil, nil
}

// AcceptUntil records an accept like UpdateStatusBatch does.
func (m *mockFindingRepository) AcceptUntil(ctx context.Context, tenantID, id shared.ID, _ time.Time, by *shared.ID, reason vulnerability.ClosureReason) error {
	return m.UpdateStatusBatch(ctx, tenantID, []shared.ID{id}, vulnerability.FindingStatusAccepted, "", by, vulnerability.Closure{Reason: reason})
}

func (m *mockFindingRepository) UpdateStatusBatch(_ context.Context, tenantID shared.ID, ids []shared.ID, status vulnerability.FindingStatus, resolution string, resolvedBy *shared.ID, closure vulnerability.Closure) error {
	if m.statusBatchErr != nil {
		return m.statusBatchErr
	}
	m.statusUpdates = append(m.statusUpdates, statusBatchCall{
		TenantID:   tenantID,
		IDs:        ids,
		Status:     status,
		Resolution: resolution,
		ResolvedBy: resolvedBy,
		Closure:    closure,
	})
	return nil
}
func (m *mockFindingRepository) DeleteByAssetID(_ context.Context, _, _ shared.ID) error {
	return nil
}
func (m *mockFindingRepository) DeleteByScanID(_ context.Context, _ shared.ID, _ string) error {
	return nil
}
func (m *mockFindingRepository) GetStats(_ context.Context, _ shared.ID, _ *shared.ID, _ vulnerability.FindingStatsFilter) (*vulnerability.FindingStats, error) {
	return nil, nil
}
func (m *mockFindingRepository) CountBySeverityForScan(_ context.Context, _ shared.ID, _ string) (vulnerability.SeverityCounts, error) {
	return vulnerability.SeverityCounts{}, nil
}
func (m *mockFindingRepository) AutoReopenByFingerprintsBatch(_ context.Context, _ shared.ID, _ []string) (map[string]vulnerability.ReopenedFinding, error) {
	return nil, nil
}
func (m *mockFindingRepository) ExpireFeatureBranchFindings(_ context.Context, _ shared.ID, _ int) (int64, error) {
	return 0, nil
}
func (m *mockFindingRepository) ExistsByIDs(_ context.Context, _ shared.ID, _ []shared.ID) (map[shared.ID]bool, error) {
	return nil, nil
}

func (m *mockFindingRepository) GetByFingerprintsBatch(_ context.Context, _ shared.ID, _ []string) (map[string]*vulnerability.Finding, error) {
	return nil, nil
}

func (m *mockFindingRepository) EnrichBatchByFingerprints(_ context.Context, _ shared.ID, _ []*vulnerability.Finding, _ string) (int64, error) {
	return 0, nil
}

// =============================================================================
// Mock: VulnerabilityRepository (minimal stub)
// =============================================================================

type mockVulnerabilityRepository struct{}

func (m *mockVulnerabilityRepository) Create(_ context.Context, _ *vulnerability.Vulnerability) error {
	return nil
}
func (m *mockVulnerabilityRepository) GetByID(_ context.Context, _ shared.ID) (*vulnerability.Vulnerability, error) {
	return nil, nil
}
func (m *mockVulnerabilityRepository) GetByCVE(_ context.Context, _ string) (*vulnerability.Vulnerability, error) {
	return nil, nil
}
func (m *mockVulnerabilityRepository) Update(_ context.Context, _ *vulnerability.Vulnerability) error {
	return nil
}
func (m *mockVulnerabilityRepository) Delete(_ context.Context, _ shared.ID) error {
	return nil
}
func (m *mockVulnerabilityRepository) List(_ context.Context, _ vulnerability.VulnerabilityFilter, _ vulnerability.VulnerabilityListOptions, _ pagination.Pagination) (pagination.Result[*vulnerability.Vulnerability], error) {
	return pagination.Result[*vulnerability.Vulnerability]{}, nil
}
func (m *mockVulnerabilityRepository) Count(_ context.Context, _ vulnerability.VulnerabilityFilter) (int64, error) {
	return 0, nil
}
func (m *mockVulnerabilityRepository) UpsertByCVE(_ context.Context, _ *vulnerability.Vulnerability) error {
	return nil
}
func (m *mockVulnerabilityRepository) UpsertBatchByCVE(_ context.Context, _ []*vulnerability.Vulnerability) error {
	return nil
}
func (m *mockVulnerabilityRepository) ExistsByCVE(_ context.Context, _ string) (bool, error) {
	return false, nil
}

// =============================================================================
// Helper: create VulnerabilityService with mocks and approval repo wired
// =============================================================================

func newApprovalTestService(
	findingRepo *mockFindingRepository,
	approvalRepo *mockApprovalRepository,
) *finding.VulnerabilityService {
	vulnRepo := &mockVulnerabilityRepository{}
	log := logger.NewNop()
	svc := finding.NewVulnerabilityService(vulnRepo, findingRepo, log)
	approvalRepo.findings = findingRepo
	svc.SetApprovalRepository(approvalRepo)
	return svc
}

// =============================================================================
// Tests: RequestApproval
// =============================================================================

func TestFindingApprovalService_RequestApproval_Success(t *testing.T) {
	tenantID := shared.NewID()
	findingID := shared.NewID()
	requestedBy := shared.NewID()

	findingRepo := newMockFindingRepository()
	// We need a Finding to exist. Since Finding has unexported fields,
	// we store a nil entry to indicate existence; the mock GetByID checks the map.
	// Instead, we set findingRepo.getByIDErr to nil and rely on the key existing.
	// We need to add a real Finding to the map. Let's use a different approach:
	// just ensure the finding exists by having GetByID not return an error.
	// Since Finding has unexported fields, we'll use a pointer that the service won't dereference.
	findingRepo.findings[findingID] = newApprovalTestFinding(t)

	approvalRepo := newMockApprovalRepository()
	svc := newApprovalTestService(findingRepo, approvalRepo)

	input := finding.RequestApprovalInput{
		TenantID:        tenantID.String(),
		FindingID:       findingID.String(),
		RequestedStatus: "false_positive",
		ClosureReason:   "detection_error",
		Justification:   "This is a known test pattern and not a real vulnerability",
		RequestedBy:     requestedBy.String(),
	}

	approval, err := svc.RequestApproval(context.Background(), input)

	require.NoError(t, err)
	require.NotNil(t, approval)
	assert.Equal(t, vulnerability.ApprovalStatusPending, approval.Status)
	assert.Equal(t, tenantID, approval.TenantID)
	assert.Equal(t, findingID, approval.FindingID)
	assert.Equal(t, requestedBy, approval.RequestedBy)
	assert.Equal(t, "false_positive", approval.RequestedStatus)
	assert.Equal(t, "This is a known test pattern and not a real vulnerability", approval.Justification)

	// Verify it was stored
	assert.Len(t, approvalRepo.approvals, 1)
}

// The approval workflow must only accept statuses that require approval
// (false_positive / accepted / accepted_risk). Requesting e.g. "resolved"
// would otherwise launder a finding past the findings:verify gate and the
// state machine once approved.
func TestFindingApprovalService_RequestApproval_RejectsNonApprovalStatus(t *testing.T) {
	for _, status := range []string{"resolved", "confirmed", "in_progress", "fix_applied"} {
		t.Run(status, func(t *testing.T) {
			tenantID := shared.NewID()
			findingID := shared.NewID()
			findingRepo := newMockFindingRepository()
			findingRepo.findings[findingID] = newApprovalTestFinding(t)
			approvalRepo := newMockApprovalRepository()
			svc := newApprovalTestService(findingRepo, approvalRepo)

			_, err := svc.RequestApproval(context.Background(), finding.RequestApprovalInput{
				TenantID:        tenantID.String(),
				FindingID:       findingID.String(),
				RequestedStatus: status,
				ClosureReason:   testClosureReason(status),
				Justification:   "trying to launder status via approval",
				RequestedBy:     shared.NewID().String(),
			})
			require.Error(t, err)
			assert.True(t, errors.Is(err, shared.ErrValidation), "want validation error, got %v", err)
			assert.Empty(t, approvalRepo.approvals, "no approval should be stored")
		})
	}
}

func TestFindingApprovalService_RequestApproval_FindingNotFound(t *testing.T) {
	tenantID := shared.NewID()
	findingID := shared.NewID()
	requestedBy := shared.NewID()

	findingRepo := newMockFindingRepository()
	// Don't add finding to the repo - it won't be found
	approvalRepo := newMockApprovalRepository()
	svc := newApprovalTestService(findingRepo, approvalRepo)

	input := finding.RequestApprovalInput{
		TenantID:        tenantID.String(),
		FindingID:       findingID.String(),
		RequestedStatus: "false_positive",
		ClosureReason:   "detection_error",
		Justification:   "Test justification",
		RequestedBy:     requestedBy.String(),
	}

	approval, err := svc.RequestApproval(context.Background(), input)

	assert.Error(t, err, "should fail when finding does not exist")
	assert.Nil(t, approval)
	assert.True(t, errors.Is(err, shared.ErrNotFound), "error should be ErrNotFound")
}

func TestFindingApprovalService_RequestApproval_InvalidIDs(t *testing.T) {
	findingRepo := newMockFindingRepository()
	approvalRepo := newMockApprovalRepository()
	svc := newApprovalTestService(findingRepo, approvalRepo)

	tests := []struct {
		name  string
		input finding.RequestApprovalInput
	}{
		{
			name: "invalid tenant ID",
			input: finding.RequestApprovalInput{
				TenantID:        "not-a-uuid",
				FindingID:       shared.NewID().String(),
				RequestedStatus: "false_positive",
				ClosureReason:   "detection_error",
				Justification:   "Test",
				RequestedBy:     shared.NewID().String(),
			},
		},
		{
			name: "invalid finding ID",
			input: finding.RequestApprovalInput{
				TenantID:        shared.NewID().String(),
				FindingID:       "not-a-uuid",
				RequestedStatus: "false_positive",
				ClosureReason:   "detection_error",
				Justification:   "Test",
				RequestedBy:     shared.NewID().String(),
			},
		},
		{
			name: "invalid requested_by ID",
			input: finding.RequestApprovalInput{
				TenantID:        shared.NewID().String(),
				FindingID:       shared.NewID().String(),
				RequestedStatus: "false_positive",
				ClosureReason:   "detection_error",
				Justification:   "Test",
				RequestedBy:     "not-a-uuid",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			approval, err := svc.RequestApproval(context.Background(), tt.input)

			assert.Error(t, err)
			assert.Nil(t, approval)
			assert.True(t, errors.Is(err, shared.ErrValidation), "should return validation error for invalid IDs")
		})
	}
}

// =============================================================================
// Tests: ApproveStatus
// =============================================================================

func TestFindingApprovalService_ApproveStatus_Success(t *testing.T) {
	tenantID := shared.NewID()
	findingID := shared.NewID()
	requestedBy := shared.NewID()
	approverID := shared.NewID()

	findingRepo := newMockFindingRepository()
	findingRepo.findings[findingID] = newApprovalTestFinding(t)
	approvalRepo := newMockApprovalRepository()
	svc := newApprovalTestService(findingRepo, approvalRepo)

	// First, create an approval
	requestInput := finding.RequestApprovalInput{
		TenantID:        tenantID.String(),
		FindingID:       findingID.String(),
		RequestedStatus: "false_positive",
		ClosureReason:   "detection_error",
		Justification:   "Known test pattern",
		RequestedBy:     requestedBy.String(),
	}
	created, err := svc.RequestApproval(context.Background(), requestInput)
	require.NoError(t, err)

	// Now approve it
	approveInput := finding.ApproveStatusInput{
		TenantID:   tenantID.String(),
		ApprovalID: created.ID.String(),
		ApprovedBy: approverID.String(),
	}

	approval, err := svc.ApproveStatus(context.Background(), approveInput)

	require.NoError(t, err)
	require.NotNil(t, approval)
	assert.Equal(t, vulnerability.ApprovalStatusApproved, approval.Status)
	require.NotNil(t, approval.ApprovedBy)
	assert.Equal(t, approverID, *approval.ApprovedBy)

	// Verify the finding status was also updated via UpdateStatusBatch
	require.Len(t, findingRepo.statusUpdates, 1)
	assert.Equal(t, tenantID, findingRepo.statusUpdates[0].TenantID)
	assert.Equal(t, []shared.ID{findingID}, findingRepo.statusUpdates[0].IDs)
	assert.Equal(t, vulnerability.FindingStatus("false_positive"), findingRepo.statusUpdates[0].Status)
}

func TestFindingApprovalService_ApproveStatus_NotFound(t *testing.T) {
	tenantID := shared.NewID()
	approverID := shared.NewID()
	fakeApprovalID := shared.NewID()

	findingRepo := newMockFindingRepository()
	approvalRepo := newMockApprovalRepository()
	svc := newApprovalTestService(findingRepo, approvalRepo)

	input := finding.ApproveStatusInput{
		TenantID:   tenantID.String(),
		ApprovalID: fakeApprovalID.String(),
		ApprovedBy: approverID.String(),
	}

	approval, err := svc.ApproveStatus(context.Background(), input)

	assert.Error(t, err)
	assert.Nil(t, approval)
	assert.True(t, errors.Is(err, shared.ErrNotFound))
}

func TestFindingApprovalService_ApproveStatus_AlreadyApproved(t *testing.T) {
	tenantID := shared.NewID()
	findingID := shared.NewID()
	requestedBy := shared.NewID()
	approverID := shared.NewID()

	findingRepo := newMockFindingRepository()
	findingRepo.findings[findingID] = newApprovalTestFinding(t)
	approvalRepo := newMockApprovalRepository()
	svc := newApprovalTestService(findingRepo, approvalRepo)

	// Create and approve
	created, err := svc.RequestApproval(context.Background(), finding.RequestApprovalInput{
		TenantID:        tenantID.String(),
		FindingID:       findingID.String(),
		RequestedStatus: "false_positive",
		ClosureReason:   "detection_error",
		Justification:   "Test",
		RequestedBy:     requestedBy.String(),
	})
	require.NoError(t, err)

	_, err = svc.ApproveStatus(context.Background(), finding.ApproveStatusInput{
		TenantID:   tenantID.String(),
		ApprovalID: created.ID.String(),
		ApprovedBy: approverID.String(),
	})
	require.NoError(t, err)

	// Try to approve again
	approval, err := svc.ApproveStatus(context.Background(), finding.ApproveStatusInput{
		TenantID:   tenantID.String(),
		ApprovalID: created.ID.String(),
		ApprovedBy: approverID.String(),
	})

	assert.Error(t, err, "should not be able to approve an already-approved approval")
	assert.Nil(t, approval)
	assert.Contains(t, err.Error(), "not pending")
}

func TestFindingApprovalService_ApproveStatus_Expired(t *testing.T) {
	tenantID := shared.NewID()
	findingID := shared.NewID()
	requestedBy := shared.NewID()
	approverID := shared.NewID()

	findingRepo := newMockFindingRepository()
	findingRepo.findings[findingID] = newApprovalTestFinding(t)
	approvalRepo := newMockApprovalRepository()
	svc := newApprovalTestService(findingRepo, approvalRepo)

	// An acceptance request whose end passed while it was pending.
	created, err := svc.RequestApproval(context.Background(), finding.RequestApprovalInput{
		TenantID:        tenantID.String(),
		FindingID:       findingID.String(),
		RequestedStatus: "accepted",
		ClosureReason:   "risk_accepted",
		Justification:   "Test",
		RequestedBy:     requestedBy.String(),
	})
	require.NoError(t, err)
	past := time.Now().Add(-1 * time.Hour)
	approvalRepo.approvals[created.ID].ExpiresAt = &past

	// Try to approve the expired approval
	approval, err := svc.ApproveStatus(context.Background(), finding.ApproveStatusInput{
		TenantID:   tenantID.String(),
		ApprovalID: created.ID.String(),
		ApprovedBy: approverID.String(),
	})

	assert.Error(t, err, "should not be able to approve an expired approval")
	assert.Nil(t, approval)
	assert.Contains(t, err.Error(), "acceptance end has passed")
}

func TestFindingApprovalService_ApproveStatus_SelfApproval(t *testing.T) {
	tenantID := shared.NewID()
	findingID := shared.NewID()
	requestedBy := shared.NewID()

	findingRepo := newMockFindingRepository()
	findingRepo.findings[findingID] = newApprovalTestFinding(t)
	approvalRepo := newMockApprovalRepository()
	svc := newApprovalTestService(findingRepo, approvalRepo)

	created, err := svc.RequestApproval(context.Background(), finding.RequestApprovalInput{
		TenantID:        tenantID.String(),
		FindingID:       findingID.String(),
		RequestedStatus: "false_positive",
		ClosureReason:   "detection_error",
		Justification:   "Test",
		RequestedBy:     requestedBy.String(),
	})
	require.NoError(t, err)

	// Try to approve own request
	approval, err := svc.ApproveStatus(context.Background(), finding.ApproveStatusInput{
		TenantID:   tenantID.String(),
		ApprovalID: created.ID.String(),
		ApprovedBy: requestedBy.String(), // same as requester
	})

	assert.Error(t, err, "should not be able to approve own request")
	assert.Nil(t, approval)
	assert.ErrorIs(t, err, vulnerability.ErrSelfApproval)
}

// =============================================================================
// Tests: RejectApproval
// =============================================================================

func TestFindingApprovalService_RejectApproval_Expired(t *testing.T) {
	tenantID := shared.NewID()
	findingID := shared.NewID()
	requestedBy := shared.NewID()
	rejecterID := shared.NewID()

	findingRepo := newMockFindingRepository()
	findingRepo.findings[findingID] = newApprovalTestFinding(t)
	approvalRepo := newMockApprovalRepository()
	svc := newApprovalTestService(findingRepo, approvalRepo)

	// An acceptance request whose end passed while it was pending.
	created, err := svc.RequestApproval(context.Background(), finding.RequestApprovalInput{
		TenantID:        tenantID.String(),
		FindingID:       findingID.String(),
		RequestedStatus: "accepted",
		ClosureReason:   "risk_accepted",
		Justification:   "Test",
		RequestedBy:     requestedBy.String(),
	})
	require.NoError(t, err)
	past := time.Now().Add(-1 * time.Hour)
	approvalRepo.approvals[created.ID].DecideBy = &past

	// Try to reject a request past its decide-by time
	approval, err := svc.RejectApproval(context.Background(), finding.RejectApprovalInput{
		TenantID:   tenantID.String(),
		ApprovalID: created.ID.String(),
		RejectedBy: rejecterID.String(),
		Reason:     "Test rejection",
	})

	assert.ErrorIs(t, err, vulnerability.ErrDecisionOverdue, "a request past its decide-by time cannot be decided")
	assert.Nil(t, approval)
}

func TestFindingApprovalService_RejectApproval_Success(t *testing.T) {
	tenantID := shared.NewID()
	findingID := shared.NewID()
	requestedBy := shared.NewID()
	rejecterID := shared.NewID()

	findingRepo := newMockFindingRepository()
	findingRepo.findings[findingID] = newApprovalTestFinding(t)
	approvalRepo := newMockApprovalRepository()
	svc := newApprovalTestService(findingRepo, approvalRepo)

	// Create approval
	created, err := svc.RequestApproval(context.Background(), finding.RequestApprovalInput{
		TenantID:        tenantID.String(),
		FindingID:       findingID.String(),
		RequestedStatus: "false_positive",
		ClosureReason:   "detection_error",
		Justification:   "Test",
		RequestedBy:     requestedBy.String(),
	})
	require.NoError(t, err)

	// Reject it
	rejectInput := finding.RejectApprovalInput{
		TenantID:   tenantID.String(),
		ApprovalID: created.ID.String(),
		RejectedBy: rejecterID.String(),
		Reason:     "Insufficient evidence to classify as false positive",
	}

	approval, err := svc.RejectApproval(context.Background(), rejectInput)

	require.NoError(t, err)
	require.NotNil(t, approval)
	assert.Equal(t, vulnerability.ApprovalStatusRejected, approval.Status)
	require.NotNil(t, approval.RejectedBy)
	assert.Equal(t, rejecterID, *approval.RejectedBy)
	assert.Equal(t, "Insufficient evidence to classify as false positive", approval.RejectionReason)

	// Verify finding status was NOT changed (reject does not apply status)
	assert.Empty(t, findingRepo.statusUpdates, "rejecting should not update finding status")
}

func TestFindingApprovalService_RejectApproval_NotFound(t *testing.T) {
	tenantID := shared.NewID()
	rejecterID := shared.NewID()
	fakeApprovalID := shared.NewID()

	findingRepo := newMockFindingRepository()
	approvalRepo := newMockApprovalRepository()
	svc := newApprovalTestService(findingRepo, approvalRepo)

	input := finding.RejectApprovalInput{
		TenantID:   tenantID.String(),
		ApprovalID: fakeApprovalID.String(),
		RejectedBy: rejecterID.String(),
		Reason:     "Not found test",
	}

	approval, err := svc.RejectApproval(context.Background(), input)

	assert.Error(t, err)
	assert.Nil(t, approval)
	assert.True(t, errors.Is(err, shared.ErrNotFound))
}

func TestFindingApprovalService_RejectApproval_InvalidIDs(t *testing.T) {
	findingRepo := newMockFindingRepository()
	approvalRepo := newMockApprovalRepository()
	svc := newApprovalTestService(findingRepo, approvalRepo)

	tests := []struct {
		name  string
		input finding.RejectApprovalInput
	}{
		{
			name: "invalid tenant ID",
			input: finding.RejectApprovalInput{
				TenantID:   "bad",
				ApprovalID: shared.NewID().String(),
				RejectedBy: shared.NewID().String(),
				Reason:     "Test",
			},
		},
		{
			name: "invalid approval ID",
			input: finding.RejectApprovalInput{
				TenantID:   shared.NewID().String(),
				ApprovalID: "bad",
				RejectedBy: shared.NewID().String(),
				Reason:     "Test",
			},
		},
		{
			name: "invalid rejected_by ID",
			input: finding.RejectApprovalInput{
				TenantID:   shared.NewID().String(),
				ApprovalID: shared.NewID().String(),
				RejectedBy: "bad",
				Reason:     "Test",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			approval, err := svc.RejectApproval(context.Background(), tt.input)

			assert.Error(t, err)
			assert.Nil(t, approval)
			assert.True(t, errors.Is(err, shared.ErrValidation))
		})
	}
}

// =============================================================================
// Tests: ListApprovals
// =============================================================================

func TestFindingApprovalService_ListApprovals_Success(t *testing.T) {
	tenantID := shared.NewID()
	findingID := shared.NewID()
	requestedBy := shared.NewID()

	findingRepo := newMockFindingRepository()
	findingRepo.findings[findingID] = newApprovalTestFinding(t)
	approvalRepo := newMockApprovalRepository()
	svc := newApprovalTestService(findingRepo, approvalRepo)

	// Create 3 pending approvals
	for i := 0; i < 3; i++ {
		_, err := svc.RequestApproval(context.Background(), finding.RequestApprovalInput{
			TenantID:        tenantID.String(),
			FindingID:       findingID.String(),
			RequestedStatus: "false_positive",
			ClosureReason:   "detection_error",
			Justification:   "Test justification",
			RequestedBy:     requestedBy.String(),
		})
		require.NoError(t, err)
	}

	// Also create one in a different tenant (should not appear)
	otherTenantID := shared.NewID()
	otherFindingID := shared.NewID()
	findingRepo.findings[otherFindingID] = newApprovalTestFinding(t)
	_, err := svc.RequestApproval(context.Background(), finding.RequestApprovalInput{
		TenantID:        otherTenantID.String(),
		FindingID:       otherFindingID.String(),
		RequestedStatus: "accepted",
		ClosureReason:   "risk_accepted",
		Justification:   "Other tenant",
		RequestedBy:     requestedBy.String(),
	})
	require.NoError(t, err)

	result, err := svc.ListApprovals(context.Background(), tenantID.String(), "pending", 1, 10)

	require.NoError(t, err)
	assert.Equal(t, int64(3), result.Total, "should only see approvals for the target tenant")
	assert.Len(t, result.Data, 3)
	assert.Equal(t, 1, result.Page)
	assert.Equal(t, 10, result.PerPage)
}

func TestFindingApprovalService_ListApprovals_EmptyResult(t *testing.T) {
	tenantID := shared.NewID()

	findingRepo := newMockFindingRepository()
	approvalRepo := newMockApprovalRepository()
	svc := newApprovalTestService(findingRepo, approvalRepo)

	result, err := svc.ListApprovals(context.Background(), tenantID.String(), "pending", 1, 10)

	require.NoError(t, err)
	assert.Equal(t, int64(0), result.Total)
	assert.Empty(t, result.Data)
}

func TestFindingApprovalService_ListApprovals_InvalidTenantID(t *testing.T) {
	findingRepo := newMockFindingRepository()
	approvalRepo := newMockApprovalRepository()
	svc := newApprovalTestService(findingRepo, approvalRepo)

	_, err := svc.ListApprovals(context.Background(), "not-a-uuid", "", 1, 10)

	assert.Error(t, err)
	assert.True(t, errors.Is(err, shared.ErrValidation))
}

func TestFindingApprovalService_ListApprovals_StatusFilterAndCounts(t *testing.T) {
	tenantID := shared.NewID()
	findingID := shared.NewID()
	requester := shared.NewID()

	findingRepo := newMockFindingRepository()
	findingRepo.findings[findingID] = newApprovalTestFinding(t)
	approvalRepo := newMockApprovalRepository()
	svc := newApprovalTestService(findingRepo, approvalRepo)

	ids := make([]shared.ID, 0, 3)
	for i := 0; i < 3; i++ {
		a, err := svc.RequestApproval(context.Background(), finding.RequestApprovalInput{
			TenantID: tenantID.String(), FindingID: findingID.String(),
			RequestedStatus: "false_positive",
			ClosureReason:   "detection_error", Justification: "j", RequestedBy: requester.String(),
		})
		require.NoError(t, err)
		ids = append(ids, a.ID)
	}
	// One request was rejected (the reject path itself is tested elsewhere).
	approvalRepo.approvals[ids[0]].Status = vulnerability.ApprovalStatusRejected

	rejected, err := svc.ListApprovals(context.Background(), tenantID.String(), "rejected", 1, 10)
	require.NoError(t, err)
	assert.Equal(t, int64(1), rejected.Total)
	require.Len(t, rejected.Data, 1)
	assert.Equal(t, vulnerability.ApprovalStatusRejected, rejected.Data[0].Status)
	assert.Equal(t, int64(2), rejected.StatusCounts[vulnerability.ApprovalStatusPending])
	assert.Equal(t, int64(1), rejected.StatusCounts[vulnerability.ApprovalStatusRejected])

	all, err := svc.ListApprovals(context.Background(), tenantID.String(), "", 1, 10)
	require.NoError(t, err)
	assert.Equal(t, int64(3), all.Total, "no status filter lists every status")
}

func TestFindingApprovalService_ListApprovals_InvalidStatus(t *testing.T) {
	svc := newApprovalTestService(newMockFindingRepository(), newMockApprovalRepository())
	_, err := svc.ListApprovals(context.Background(), shared.NewID().String(), "done';--", 1, 10)
	require.Error(t, err)
	assert.True(t, errors.Is(err, shared.ErrValidation))
}

// =============================================================================
// Tests: ApprovalRepo not configured
// =============================================================================

func TestFindingApprovalService_ApprovalRepoNotConfigured(t *testing.T) {
	vulnRepo := &mockVulnerabilityRepository{}
	findingRepo := newMockFindingRepository()
	log := logger.NewNop()
	svc := finding.NewVulnerabilityService(vulnRepo, findingRepo, log)
	// Deliberately NOT calling svc.SetApprovalRepository()

	t.Run("RequestApproval", func(t *testing.T) {
		_, err := svc.RequestApproval(context.Background(), finding.RequestApprovalInput{
			TenantID:        shared.NewID().String(),
			FindingID:       shared.NewID().String(),
			RequestedStatus: "false_positive",
			ClosureReason:   "detection_error",
			Justification:   "Test",
			RequestedBy:     shared.NewID().String(),
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "approval workflow not configured")
	})

	t.Run("ApproveStatus", func(t *testing.T) {
		_, err := svc.ApproveStatus(context.Background(), finding.ApproveStatusInput{
			TenantID:   shared.NewID().String(),
			ApprovalID: shared.NewID().String(),
			ApprovedBy: shared.NewID().String(),
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "approval workflow not configured")
	})

	t.Run("RejectApproval", func(t *testing.T) {
		_, err := svc.RejectApproval(context.Background(), finding.RejectApprovalInput{
			TenantID:   shared.NewID().String(),
			ApprovalID: shared.NewID().String(),
			RejectedBy: shared.NewID().String(),
			Reason:     "Test",
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "approval workflow not configured")
	})

	t.Run("ListApprovals", func(t *testing.T) {
		_, err := svc.ListApprovals(context.Background(), shared.NewID().String(), "", 1, 10)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "approval workflow not configured")
	})

	t.Run("CancelApproval", func(t *testing.T) {
		_, err := svc.CancelApproval(context.Background(), finding.CancelApprovalInput{
			TenantID:   shared.NewID().String(),
			ApprovalID: shared.NewID().String(),
			CanceledBy: shared.NewID().String(),
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "approval workflow not configured")
	})
}

// =============================================================================
// Tests: CancelApproval
// =============================================================================

func TestFindingApprovalService_CancelApproval_Success(t *testing.T) {
	tenantID := shared.NewID()
	findingID := shared.NewID()
	requestedBy := shared.NewID()

	findingRepo := newMockFindingRepository()
	findingRepo.findings[findingID] = newApprovalTestFinding(t)
	approvalRepo := newMockApprovalRepository()
	svc := newApprovalTestService(findingRepo, approvalRepo)

	// Create approval
	created, err := svc.RequestApproval(context.Background(), finding.RequestApprovalInput{
		TenantID:        tenantID.String(),
		FindingID:       findingID.String(),
		RequestedStatus: "false_positive",
		ClosureReason:   "detection_error",
		Justification:   "Test",
		RequestedBy:     requestedBy.String(),
	})
	require.NoError(t, err)

	// Cancel it (as the requester)
	approval, err := svc.CancelApproval(context.Background(), finding.CancelApprovalInput{
		TenantID:   tenantID.String(),
		ApprovalID: created.ID.String(),
		CanceledBy: requestedBy.String(),
	})

	require.NoError(t, err)
	require.NotNil(t, approval)
	assert.Equal(t, vulnerability.ApprovalStatusCanceled, approval.Status)

	// Verify finding status was NOT changed (cancel does not apply status)
	assert.Empty(t, findingRepo.statusUpdates, "cancelling should not update finding status")
}

func TestFindingApprovalService_CancelApproval_NotRequester(t *testing.T) {
	tenantID := shared.NewID()
	findingID := shared.NewID()
	requestedBy := shared.NewID()
	otherUser := shared.NewID()

	findingRepo := newMockFindingRepository()
	findingRepo.findings[findingID] = newApprovalTestFinding(t)
	approvalRepo := newMockApprovalRepository()
	svc := newApprovalTestService(findingRepo, approvalRepo)

	// Create approval
	created, err := svc.RequestApproval(context.Background(), finding.RequestApprovalInput{
		TenantID:        tenantID.String(),
		FindingID:       findingID.String(),
		RequestedStatus: "false_positive",
		ClosureReason:   "detection_error",
		Justification:   "Test",
		RequestedBy:     requestedBy.String(),
	})
	require.NoError(t, err)

	// Try to cancel as a different user
	approval, err := svc.CancelApproval(context.Background(), finding.CancelApprovalInput{
		TenantID:   tenantID.String(),
		ApprovalID: created.ID.String(),
		CanceledBy: otherUser.String(),
	})

	assert.Error(t, err, "only the requester should be able to cancel")
	assert.Nil(t, approval)
	assert.Contains(t, err.Error(), "only the requester")
}

func TestFindingApprovalService_CancelApproval_NotPending(t *testing.T) {
	tenantID := shared.NewID()
	findingID := shared.NewID()
	requestedBy := shared.NewID()
	approverID := shared.NewID()

	findingRepo := newMockFindingRepository()
	findingRepo.findings[findingID] = newApprovalTestFinding(t)
	approvalRepo := newMockApprovalRepository()
	svc := newApprovalTestService(findingRepo, approvalRepo)

	// Create and approve
	created, err := svc.RequestApproval(context.Background(), finding.RequestApprovalInput{
		TenantID:        tenantID.String(),
		FindingID:       findingID.String(),
		RequestedStatus: "false_positive",
		ClosureReason:   "detection_error",
		Justification:   "Test",
		RequestedBy:     requestedBy.String(),
	})
	require.NoError(t, err)

	_, err = svc.ApproveStatus(context.Background(), finding.ApproveStatusInput{
		TenantID:   tenantID.String(),
		ApprovalID: created.ID.String(),
		ApprovedBy: approverID.String(),
	})
	require.NoError(t, err)

	// Try to cancel the already-approved approval
	approval, err := svc.CancelApproval(context.Background(), finding.CancelApprovalInput{
		TenantID:   tenantID.String(),
		ApprovalID: created.ID.String(),
		CanceledBy: requestedBy.String(),
	})

	assert.Error(t, err, "should not be able to cancel an already-approved approval")
	assert.Nil(t, approval)
	assert.Contains(t, err.Error(), "not pending")
}

// =============================================================================
// Tests: RequestApproval - Invalid Status
// =============================================================================

func TestFindingApprovalService_RequestApproval_InvalidStatus(t *testing.T) {
	tenantID := shared.NewID()
	findingID := shared.NewID()
	requestedBy := shared.NewID()

	findingRepo := newMockFindingRepository()
	findingRepo.findings[findingID] = newApprovalTestFinding(t)
	approvalRepo := newMockApprovalRepository()
	svc := newApprovalTestService(findingRepo, approvalRepo)

	input := finding.RequestApprovalInput{
		TenantID:        tenantID.String(),
		FindingID:       findingID.String(),
		RequestedStatus: "invalid_garbage_status",
		ClosureReason:   testClosureReason("invalid_garbage_status"),
		Justification:   "Test justification",
		RequestedBy:     requestedBy.String(),
	}

	approval, err := svc.RequestApproval(context.Background(), input)

	assert.Error(t, err, "should reject invalid requested_status")
	assert.Nil(t, approval)
	assert.Contains(t, err.Error(), "invalid requested_status")
	assert.True(t, errors.Is(err, shared.ErrValidation))
}

// =============================================================================
// Tests: ApproveStatus - Concurrent Modification
// =============================================================================

func TestFindingApprovalService_ApproveStatus_ConcurrentModification(t *testing.T) {
	tenantID := shared.NewID()
	findingID := shared.NewID()
	requestedBy := shared.NewID()
	approverID := shared.NewID()

	findingRepo := newMockFindingRepository()
	findingRepo.findings[findingID] = newApprovalTestFinding(t)
	approvalRepo := newMockApprovalRepository()
	svc := newApprovalTestService(findingRepo, approvalRepo)

	// Create approval
	created, err := svc.RequestApproval(context.Background(), finding.RequestApprovalInput{
		TenantID:        tenantID.String(),
		FindingID:       findingID.String(),
		RequestedStatus: "false_positive",
		ClosureReason:   "detection_error",
		Justification:   "Test",
		RequestedBy:     requestedBy.String(),
	})
	require.NoError(t, err)

	// Set mock to return concurrent modification error on Update
	approvalRepo.updateErr = vulnerability.ErrConcurrentModification

	// Try to approve - should fail with concurrent modification
	approval, err := svc.ApproveStatus(context.Background(), finding.ApproveStatusInput{
		TenantID:   tenantID.String(),
		ApprovalID: created.ID.String(),
		ApprovedBy: approverID.String(),
	})

	assert.Error(t, err, "should fail with concurrent modification error")
	assert.Nil(t, approval)
	assert.ErrorIs(t, err, vulnerability.ErrConcurrentModification)
	assert.True(t, errors.Is(err, shared.ErrConflict), "should wrap ErrConflict")
}

func (m *mockFindingRepository) ListFindingGroups(_ context.Context, _ shared.ID, _ string, _ vulnerability.FindingFilter, _ pagination.Pagination) (pagination.Result[*vulnerability.FindingGroup], error) {
	return pagination.Result[*vulnerability.FindingGroup]{}, nil
}

func (m *mockFindingRepository) BulkUpdateStatusByFilter(_ context.Context, _ shared.ID, _ vulnerability.FindingFilter, _ vulnerability.FindingStatus, _ string, _ *shared.ID, _ vulnerability.Closure) (int64, error) {
	return 0, nil
}

func (m *mockFindingRepository) FindRelatedCVEs(_ context.Context, _ shared.ID, _ string, _ vulnerability.FindingFilter) ([]vulnerability.RelatedCVE, error) {
	return nil, nil
}

func (m *mockFindingRepository) ListByStatusAndAssets(_ context.Context, _ shared.ID, _ vulnerability.FindingStatus, _ []shared.ID) ([]*vulnerability.Finding, error) {
	return nil, nil
}
func (m *mockFindingRepository) GetByWorkItemURI(_ context.Context, _ shared.ID, _ string) (*vulnerability.Finding, error) {
	return nil, nil
}
func (m *mockFindingRepository) UpdateWorkItemURIs(_ context.Context, _, _ shared.ID, _ []string) error {
	return nil
}

func (m *mockFindingRepository) ListComponentCVEPairs(_ context.Context, _ shared.ID, _ vulnerability.ComponentCVEFilter, _ pagination.Pagination) (pagination.Result[*vulnerability.ComponentCVEPair], error) {
	return pagination.Result[*vulnerability.ComponentCVEPair]{}, nil
}

func (m *mockFindingRepository) UpsertBranchOccurrences(_ context.Context, _ shared.ID, _ []vulnerability.BranchOccurrenceUpsert) error {
	return nil
}

func (m *mockFindingRepository) BackfillFindingBranches(_ context.Context, _ shared.ID, _ []vulnerability.BranchOccurrenceUpsert) (int64, error) {
	return 0, nil
}

func (m *mockFindingRepository) AutoResolveStaleBranchOccurrences(_ context.Context, _, _ shared.ID, _, _ string) (int64, error) {
	return 0, nil
}

func (m *mockFindingRepository) FingerprintsOpenOnBranch(_ context.Context, _, _ shared.ID, _ []string) ([]string, error) {
	return nil, nil
}

// An approver reads what a request is about: the list carries each
// finding title, read only within the caller tenant.
func TestFindingApprovalService_ApprovalFindingTitles_TenantScoped(t *testing.T) {
	tenantID, otherTenant := shared.NewID(), shared.NewID()
	newFinding := func(tenant shared.ID, title string) *vulnerability.Finding {
		f, err := vulnerability.NewFinding(tenant, shared.NewID(), vulnerability.FindingSourceManual, "manual", vulnerability.SeverityHigh, "msg")
		require.NoError(t, err)
		f.SetTitle(title)
		return f
	}
	mine := newFinding(tenantID, "SQL injection in /login")
	theirs := newFinding(otherTenant, "Other tenant finding")

	findingRepo := newMockFindingRepository()
	findingRepo.findings[mine.ID()] = mine
	findingRepo.findings[theirs.ID()] = theirs
	svc := newApprovalTestService(findingRepo, newMockApprovalRepository())

	gone := shared.NewID()
	approvals := []*vulnerability.Approval{
		{FindingID: mine.ID()}, {FindingID: mine.ID()}, {FindingID: theirs.ID()}, {FindingID: gone},
	}
	titles, err := svc.ApprovalFindingTitles(context.Background(), tenantID.String(), approvals)
	require.NoError(t, err)
	assert.Equal(t, map[shared.ID]string{mine.ID(): "SQL injection in /login"}, titles,
		"another tenant finding or a deleted finding has no title")

	empty, err := svc.ApprovalFindingTitles(context.Background(), tenantID.String(), nil)
	require.NoError(t, err)
	assert.Empty(t, empty)

	_, err = svc.ApprovalFindingTitles(context.Background(), "not-a-uuid", approvals)
	assert.True(t, errors.Is(err, shared.ErrValidation))
}

// newApprovalTestFinding is a confirmed finding: both approval-gated
// dispositions (false_positive, accepted) are lifecycle moves from it.
func newApprovalTestFinding(t *testing.T) *vulnerability.Finding {
	t.Helper()
	f, err := vulnerability.NewFinding(shared.NewID(), shared.NewID(), vulnerability.FindingSourceSAST, "test-tool", vulnerability.SeverityHigh, "Test finding")
	require.NoError(t, err)
	require.NoError(t, f.TransitionStatus(vulnerability.FindingStatusConfirmed, "", nil))
	return f
}

func TestFindingApprovalService_RequestApproval_DecisionEnd(t *testing.T) {
	tenantID := shared.NewID()
	findingID := shared.NewID()
	requestedBy := shared.NewID()

	findingRepo := newMockFindingRepository()
	findingRepo.findings[findingID] = newApprovalTestFinding(t)
	approvalRepo := newMockApprovalRepository()
	svc := newApprovalTestService(findingRepo, approvalRepo)
	req := func(status string, end *string) (*vulnerability.Approval, error) {
		return svc.RequestApproval(context.Background(), finding.RequestApprovalInput{
			TenantID: tenantID.String(), FindingID: findingID.String(), RequestedStatus: status, ClosureReason: testClosureReason(status),
			Justification: "Test", RequestedBy: requestedBy.String(), ExpiresAt: end,
		})
	}
	str := func(t time.Time) *string { s := t.Format(time.RFC3339); return &s }

	a, err := req("accepted", nil)
	require.NoError(t, err)
	require.NotNil(t, a.ExpiresAt, "an accepted risk always ends")
	assert.WithinDuration(t, time.Now().Add(vulnerability.DefaultAcceptanceDuration), *a.ExpiresAt, time.Minute)

	_, err = req("accepted", str(time.Now().AddDate(1, 0, 2)))
	assert.ErrorIs(t, err, shared.ErrValidation, "more than a year ahead is refused")
	_, err = req("accepted", str(time.Now().Add(-time.Hour)))
	assert.ErrorIs(t, err, shared.ErrValidation, "an end in the past is refused")
	_, err = req("false_positive", str(time.Now().Add(24*time.Hour)))
	assert.ErrorIs(t, err, shared.ErrValidation, "a false positive does not expire")

	fp, err := req("false_positive", nil)
	require.NoError(t, err)
	assert.Nil(t, fp.ExpiresAt)
}

func TestFindingApprovalService_ApproveAccepted_StoresAcceptanceEnd(t *testing.T) {
	tenantID := shared.NewID()
	findingID := shared.NewID()
	findingRepo := newMockFindingRepository()
	findingRepo.findings[findingID] = newApprovalTestFinding(t)
	approvalRepo := newMockApprovalRepository()
	svc := newApprovalTestService(findingRepo, approvalRepo)

	created, err := svc.RequestApproval(context.Background(), finding.RequestApprovalInput{
		TenantID: tenantID.String(), FindingID: findingID.String(), RequestedStatus: "accepted", ClosureReason: "risk_accepted",
		Justification: "Test", RequestedBy: shared.NewID().String(),
	})
	require.NoError(t, err)
	// A request from before the end was required has none.
	approvalRepo.approvals[created.ID].ExpiresAt = nil

	approved, err := svc.ApproveStatus(context.Background(), finding.ApproveStatusInput{
		TenantID: tenantID.String(), ApprovalID: created.ID.String(), ApprovedBy: shared.NewID().String(),
	})
	require.NoError(t, err)
	require.NotNil(t, approved.ExpiresAt, "approving gives an endless acceptance the default end")
	assert.WithinDuration(t, time.Now().Add(vulnerability.DefaultAcceptanceDuration), *approved.ExpiresAt, time.Minute)
}

// testClosureReason is a reason the requested status accepts ("" when it
// accepts none), so a request fails, or passes, for the reason under test.
func testClosureReason(status string) string {
	if rs := vulnerability.PersonClosureReasons(vulnerability.FindingStatus(status)); len(rs) > 0 {
		return string(rs[0])
	}
	return ""
}

// A false-positive or accepted-risk request names a VEX-aligned reason of
// its own status, and the approval applies exactly that reason: a false
// positive as security-reviewed (a second person decided), an accepted risk
// with its reason and no verification.
func TestFindingApprovalService_ClosureReason(t *testing.T) {
	tenantID, findingID := shared.NewID(), shared.NewID()
	findingRepo := newMockFindingRepository()
	findingRepo.findings[findingID] = newApprovalTestFinding(t)
	approvalRepo := newMockApprovalRepository()
	svc := newApprovalTestService(findingRepo, approvalRepo)
	request := func(status, reason string) (*vulnerability.Approval, error) {
		return svc.RequestApproval(context.Background(), finding.RequestApprovalInput{
			TenantID: tenantID.String(), FindingID: findingID.String(), RequestedStatus: status,
			ClosureReason: reason, Justification: "why", RequestedBy: shared.NewID().String(),
		})
	}

	for name, c := range map[string][2]string{
		"no reason":                   {"false_positive", ""},
		"reason of another status":    {"false_positive", "risk_accepted"},
		"platform-only reason":        {"accepted", "unknown"},
		"made-up reason":              {"accepted", "because"},
		"resolved reason on accepted": {"accepted", "fixed"},
	} {
		_, err := request(c[0], c[1])
		require.ErrorIs(t, err, shared.ErrValidation, name)
	}

	fp, err := request("false_positive", "vulnerable_code_not_in_execute_path")
	require.NoError(t, err)
	assert.Equal(t, vulnerability.ClosureReasonVulnerableCodeNotInExecutePath, fp.ClosureReason)
	_, err = svc.ApproveStatus(context.Background(), finding.ApproveStatusInput{
		TenantID: tenantID.String(), ApprovalID: fp.ID.String(), ApprovedBy: shared.NewID().String(),
	})
	require.NoError(t, err)
	require.Len(t, findingRepo.statusUpdates, 1)
	assert.Equal(t, vulnerability.Closure{
		Reason:       vulnerability.ClosureReasonVulnerableCodeNotInExecutePath,
		Verification: vulnerability.VerificationSecurityReview,
	}, findingRepo.statusUpdates[0].Closure)

	// The finding is a false positive now (the mock does not move it):
	// reset it to confirmed for the accepted-risk request.
	findingRepo.findings[findingID] = newApprovalTestFinding(t)
	acc, err := request("accepted", "compensating_control")
	require.NoError(t, err)
	_, err = svc.ApproveStatus(context.Background(), finding.ApproveStatusInput{
		TenantID: tenantID.String(), ApprovalID: acc.ID.String(), ApprovedBy: shared.NewID().String(),
	})
	require.NoError(t, err)
	require.Len(t, findingRepo.statusUpdates, 2)
	assert.Equal(t, vulnerability.Closure{Reason: vulnerability.ClosureReasonCompensatingControl},
		findingRepo.statusUpdates[1].Closure)
}

// An accepted risk is capped by the finding's priority: a request past the
// cap is refused (never shortened), a request with no end gets the cap when
// it is shorter than the default, and an approval past the finding's cap now
// (its priority rose after the request) is refused too.
func TestFindingApprovalService_AcceptanceCapByPriority(t *testing.T) {
	tenantID, findingID := shared.NewID(), shared.NewID()
	findingRepo := newMockFindingRepository()
	f := newApprovalTestFinding(t)
	findingRepo.findings[findingID] = f
	approvalRepo := newMockApprovalRepository()
	svc := newApprovalTestService(findingRepo, approvalRepo)
	request := func(end *time.Time) (*vulnerability.Approval, error) {
		var s *string
		if end != nil {
			v := end.Format(time.RFC3339)
			s = &v
		}
		return svc.RequestApproval(context.Background(), finding.RequestApprovalInput{
			TenantID: tenantID.String(), FindingID: findingID.String(), RequestedStatus: "accepted",
			ClosureReason: "risk_accepted", Justification: "why", RequestedBy: shared.NewID().String(), ExpiresAt: s,
		})
	}
	day := 24 * time.Hour
	at := func(d time.Duration) *time.Time { v := time.Now().Add(d); return &v }

	// P2: 180 days allowed, 200 refused.
	f.SetPriorityClassification(vulnerability.PriorityP2, "test")
	_, err := request(at(170 * day))
	require.NoError(t, err)
	_, err = request(at(200 * day))
	require.ErrorIs(t, err, shared.ErrValidation, "an end past the P2 cap is refused")

	// KEV: 30 days; no end means 30 days, not the 90-day default.
	f.SetIsInKEV(true)
	kev, err := request(nil)
	require.NoError(t, err)
	require.NotNil(t, kev.ExpiresAt)
	assert.WithinDuration(t, time.Now().Add(30*day), *kev.ExpiresAt, time.Minute)
	_, err = request(at(60 * day))
	require.ErrorIs(t, err, shared.ErrValidation, "an end past the KEV cap is refused")

	// A P3 request for 300 days, then the finding becomes P0: approval refused.
	f.SetIsInKEV(false)
	f.SetPriorityClassification(vulnerability.PriorityP3, "test")
	long, err := request(at(300 * day))
	require.NoError(t, err)
	f.SetPriorityClassification(vulnerability.PriorityP0, "test")
	_, err = svc.ApproveStatus(context.Background(), finding.ApproveStatusInput{
		TenantID: tenantID.String(), ApprovalID: long.ID.String(), ApprovedBy: shared.NewID().String(),
	})
	require.ErrorIs(t, err, shared.ErrValidation, "approving past the current cap is refused")
	assert.Empty(t, findingRepo.statusUpdates, "nothing was accepted")
}

// stubLifecycles gives the service one organization scheme.
type stubLifecycles struct{ cands []lc.Candidate }

func (s stubLifecycles) Candidates(context.Context, shared.ID) ([]lc.Candidate, error) {
	return s.cands, nil
}

// Approving runs the organization's lifecycle again with the approver as the
// actor: a scheme that now needs a permission the approver does not hold
// refuses the approval, which stays pending.
func TestFindingApprovalService_ApproveStatus_LifecycleDecidesForTheApprover(t *testing.T) {
	tenantID, findingID := shared.NewID(), shared.NewID()
	findingRepo := newMockFindingRepository()
	findingRepo.findings[findingID] = newApprovalTestFinding(t)
	approvalRepo := newMockApprovalRepository()
	svc := newApprovalTestService(findingRepo, approvalRepo)

	created, err := svc.RequestApproval(context.Background(), finding.RequestApprovalInput{
		TenantID: tenantID.String(), FindingID: findingID.String(), RequestedStatus: "false_positive",
		ClosureReason: "detection_error", Justification: "Known test pattern", RequestedBy: shared.NewID().String(),
	})
	require.NoError(t, err)

	scheme, v := lc.Compile(lc.Spec{Transitions: []lc.TransitionSpec{{
		ID: "fp", Name: "False positive", From: []string{"status:confirmed"}, To: "status:false_positive",
		Guards: []lc.Guard{{Kind: lc.GuardRequirePermission, AnyOf: []string{"findings:verify"}}},
	}}}, nil, lc.Meta{VersionID: shared.NewID(), Version: 1})
	require.True(t, v.OK(), "%+v", v.Errors)
	svc.SetLifecycles(stubLifecycles{cands: []lc.Candidate{{Scheme: scheme, Default: true}}})

	_, err = svc.ApproveStatus(context.Background(), finding.ApproveStatusInput{
		TenantID: tenantID.String(), ApprovalID: created.ID.String(), ApprovedBy: shared.NewID().String(),
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, finding.ErrLifecycleMove), "got %v", err)
	assert.Empty(t, findingRepo.statusUpdates, "the finding must not move")
}
