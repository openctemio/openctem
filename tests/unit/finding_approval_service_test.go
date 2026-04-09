package unit

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"

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

func (m *mockApprovalRepository) ListPending(_ context.Context, tenantID shared.ID, page pagination.Pagination) (pagination.Result[*vulnerability.Approval], error) {
	result := make([]*vulnerability.Approval, 0)
	for _, a := range m.approvals {
		if a.TenantID == tenantID && a.Status == vulnerability.ApprovalStatusPending {
			result = append(result, a)
		}
	}
	total := int64(len(result))

	// Apply basic pagination
	start := (page.Page - 1) * page.PerPage
	if start > int(total) {
		start = int(total)
	}
	end := start + page.PerPage
	if end > int(total) {
		end = int(total)
	}

	totalPages := 1
	if total > 0 {
		totalPages = int((total + int64(page.PerPage) - 1) / int64(page.PerPage))
	}

	return pagination.Result[*vulnerability.Approval]{
		Data:       result[start:end],
		Total:      total,
		Page:       page.Page,
		PerPage:    page.PerPage,
		TotalPages: totalPages,
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
func (m *mockFindingRepository) GetByIDs(_ context.Context, _ shared.ID, _ []shared.ID) ([]*vulnerability.Finding, error) {
	return nil, nil
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
func (m *mockFindingRepository) UpdateScanIDBatchByFingerprints(_ context.Context, _ shared.ID, _ []string, _ string) (int64, error) {
	return 0, nil
}
func (m *mockFindingRepository) UpdateSnippetBatchByFingerprints(_ context.Context, _ shared.ID, _ map[string]string) (int64, error) {
	return 0, nil
}
func (m *mockFindingRepository) BatchCountByAssetIDs(_ context.Context, _ shared.ID, _ []shared.ID) (map[shared.ID]int64, error) {
	return nil, nil
}
func (m *mockFindingRepository) UpdateStatusBatch(_ context.Context, tenantID shared.ID, ids []shared.ID, status vulnerability.FindingStatus, resolution string, resolvedBy *shared.ID) error {
	if m.statusBatchErr != nil {
		return m.statusBatchErr
	}
	m.statusUpdates = append(m.statusUpdates, statusBatchCall{
		TenantID:   tenantID,
		IDs:        ids,
		Status:     status,
		Resolution: resolution,
		ResolvedBy: resolvedBy,
	})
	return nil
}
func (m *mockFindingRepository) DeleteByAssetID(_ context.Context, _, _ shared.ID) error {
	return nil
}
func (m *mockFindingRepository) DeleteByScanID(_ context.Context, _ shared.ID, _ string) error {
	return nil
}
func (m *mockFindingRepository) GetStats(_ context.Context, _ shared.ID, _ *shared.ID, _ *shared.ID) (*vulnerability.FindingStats, error) {
	return nil, nil
}
func (m *mockFindingRepository) CountBySeverityForScan(_ context.Context, _ shared.ID, _ string) (vulnerability.SeverityCounts, error) {
	return vulnerability.SeverityCounts{}, nil
}
func (m *mockFindingRepository) AutoResolveStale(_ context.Context, _ shared.ID, _ shared.ID, _ string, _ string, _ *shared.ID) ([]shared.ID, error) {
	return nil, nil
}
func (m *mockFindingRepository) AutoReopenByFingerprint(_ context.Context, _ shared.ID, _ string) (*shared.ID, error) {
	return nil, nil
}
func (m *mockFindingRepository) AutoReopenByFingerprintsBatch(_ context.Context, _ shared.ID, _ []string) (map[string]shared.ID, error) {
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
func (m *mockVulnerabilityRepository) ExistsByCVE(_ context.Context, _ string) (bool, error) {
	return false, nil
}

// =============================================================================
// Helper: create VulnerabilityService with mocks and approval repo wired
// =============================================================================

func newApprovalTestService(
	findingRepo *mockFindingRepository,
	approvalRepo *mockApprovalRepository,
) *app.VulnerabilityService {
	vulnRepo := &mockVulnerabilityRepository{}
	log := logger.NewNop()
	svc := app.NewVulnerabilityService(vulnRepo, findingRepo, log)
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
	findingRepo.findings[findingID] = &vulnerability.Finding{}

	approvalRepo := newMockApprovalRepository()
	svc := newApprovalTestService(findingRepo, approvalRepo)

	input := app.RequestApprovalInput{
		TenantID:        tenantID.String(),
		FindingID:       findingID.String(),
		RequestedStatus: "false_positive",
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

func TestFindingApprovalService_RequestApproval_FindingNotFound(t *testing.T) {
	tenantID := shared.NewID()
	findingID := shared.NewID()
	requestedBy := shared.NewID()

	findingRepo := newMockFindingRepository()
	// Don't add finding to the repo - it won't be found
	approvalRepo := newMockApprovalRepository()
	svc := newApprovalTestService(findingRepo, approvalRepo)

	input := app.RequestApprovalInput{
		TenantID:        tenantID.String(),
		FindingID:       findingID.String(),
		RequestedStatus: "false_positive",
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
		input app.RequestApprovalInput
	}{
		{
			name: "invalid tenant ID",
			input: app.RequestApprovalInput{
				TenantID:        "not-a-uuid",
				FindingID:       shared.NewID().String(),
				RequestedStatus: "false_positive",
				Justification:   "Test",
				RequestedBy:     shared.NewID().String(),
			},
		},
		{
			name: "invalid finding ID",
			input: app.RequestApprovalInput{
				TenantID:        shared.NewID().String(),
				FindingID:       "not-a-uuid",
				RequestedStatus: "false_positive",
				Justification:   "Test",
				RequestedBy:     shared.NewID().String(),
			},
		},
		{
			name: "invalid requested_by ID",
			input: app.RequestApprovalInput{
				TenantID:        shared.NewID().String(),
				FindingID:       shared.NewID().String(),
				RequestedStatus: "false_positive",
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
	findingRepo.findings[findingID] = &vulnerability.Finding{}
	approvalRepo := newMockApprovalRepository()
	svc := newApprovalTestService(findingRepo, approvalRepo)

	// First, create an approval
	requestInput := app.RequestApprovalInput{
		TenantID:        tenantID.String(),
		FindingID:       findingID.String(),
		RequestedStatus: "false_positive",
		Justification:   "Known test pattern",
		RequestedBy:     requestedBy.String(),
	}
	created, err := svc.RequestApproval(context.Background(), requestInput)
	require.NoError(t, err)

	// Now approve it
	approveInput := app.ApproveStatusInput{
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

	input := app.ApproveStatusInput{
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
	findingRepo.findings[findingID] = &vulnerability.Finding{}
	approvalRepo := newMockApprovalRepository()
	svc := newApprovalTestService(findingRepo, approvalRepo)

	// Create and approve
	created, err := svc.RequestApproval(context.Background(), app.RequestApprovalInput{
		TenantID:        tenantID.String(),
		FindingID:       findingID.String(),
		RequestedStatus: "false_positive",
		Justification:   "Test",
		RequestedBy:     requestedBy.String(),
	})
	require.NoError(t, err)

	_, err = svc.ApproveStatus(context.Background(), app.ApproveStatusInput{
		TenantID:   tenantID.String(),
		ApprovalID: created.ID.String(),
		ApprovedBy: approverID.String(),
	})
	require.NoError(t, err)

	// Try to approve again
	approval, err := svc.ApproveStatus(context.Background(), app.ApproveStatusInput{
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
	findingRepo.findings[findingID] = &vulnerability.Finding{}
	approvalRepo := newMockApprovalRepository()
	svc := newApprovalTestService(findingRepo, approvalRepo)

	// Create approval with an already-expired time
	past := time.Now().Add(-1 * time.Hour).Format(time.RFC3339)
	created, err := svc.RequestApproval(context.Background(), app.RequestApprovalInput{
		TenantID:        tenantID.String(),
		FindingID:       findingID.String(),
		RequestedStatus: "false_positive",
		Justification:   "Test",
		RequestedBy:     requestedBy.String(),
		ExpiresAt:       &past,
	})
	require.NoError(t, err)

	// Try to approve the expired approval
	approval, err := svc.ApproveStatus(context.Background(), app.ApproveStatusInput{
		TenantID:   tenantID.String(),
		ApprovalID: created.ID.String(),
		ApprovedBy: approverID.String(),
	})

	assert.Error(t, err, "should not be able to approve an expired approval")
	assert.Nil(t, approval)
	assert.Contains(t, err.Error(), "expired")
}

func TestFindingApprovalService_ApproveStatus_SelfApproval(t *testing.T) {
	tenantID := shared.NewID()
	findingID := shared.NewID()
	requestedBy := shared.NewID()

	findingRepo := newMockFindingRepository()
	findingRepo.findings[findingID] = &vulnerability.Finding{}
	approvalRepo := newMockApprovalRepository()
	svc := newApprovalTestService(findingRepo, approvalRepo)

	created, err := svc.RequestApproval(context.Background(), app.RequestApprovalInput{
		TenantID:        tenantID.String(),
		FindingID:       findingID.String(),
		RequestedStatus: "false_positive",
		Justification:   "Test",
		RequestedBy:     requestedBy.String(),
	})
	require.NoError(t, err)

	// Try to approve own request
	approval, err := svc.ApproveStatus(context.Background(), app.ApproveStatusInput{
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
	findingRepo.findings[findingID] = &vulnerability.Finding{}
	approvalRepo := newMockApprovalRepository()
	svc := newApprovalTestService(findingRepo, approvalRepo)

	// Create approval with an already-expired time
	past := time.Now().Add(-1 * time.Hour).Format(time.RFC3339)
	created, err := svc.RequestApproval(context.Background(), app.RequestApprovalInput{
		TenantID:        tenantID.String(),
		FindingID:       findingID.String(),
		RequestedStatus: "false_positive",
		Justification:   "Test",
		RequestedBy:     requestedBy.String(),
		ExpiresAt:       &past,
	})
	require.NoError(t, err)

	// Try to reject the expired approval
	approval, err := svc.RejectApproval(context.Background(), app.RejectApprovalInput{
		TenantID:   tenantID.String(),
		ApprovalID: created.ID.String(),
		RejectedBy: rejecterID.String(),
		Reason:     "Test rejection",
	})

	assert.Error(t, err, "should not be able to reject an expired approval")
	assert.Nil(t, approval)
	assert.Contains(t, err.Error(), "expired")
}

func TestFindingApprovalService_RejectApproval_Success(t *testing.T) {
	tenantID := shared.NewID()
	findingID := shared.NewID()
	requestedBy := shared.NewID()
	rejecterID := shared.NewID()

	findingRepo := newMockFindingRepository()
	findingRepo.findings[findingID] = &vulnerability.Finding{}
	approvalRepo := newMockApprovalRepository()
	svc := newApprovalTestService(findingRepo, approvalRepo)

	// Create approval
	created, err := svc.RequestApproval(context.Background(), app.RequestApprovalInput{
		TenantID:        tenantID.String(),
		FindingID:       findingID.String(),
		RequestedStatus: "false_positive",
		Justification:   "Test",
		RequestedBy:     requestedBy.String(),
	})
	require.NoError(t, err)

	// Reject it
	rejectInput := app.RejectApprovalInput{
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

	input := app.RejectApprovalInput{
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
		input app.RejectApprovalInput
	}{
		{
			name: "invalid tenant ID",
			input: app.RejectApprovalInput{
				TenantID:   "bad",
				ApprovalID: shared.NewID().String(),
				RejectedBy: shared.NewID().String(),
				Reason:     "Test",
			},
		},
		{
			name: "invalid approval ID",
			input: app.RejectApprovalInput{
				TenantID:   shared.NewID().String(),
				ApprovalID: "bad",
				RejectedBy: shared.NewID().String(),
				Reason:     "Test",
			},
		},
		{
			name: "invalid rejected_by ID",
			input: app.RejectApprovalInput{
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
// Tests: ListPendingApprovals
// =============================================================================

func TestFindingApprovalService_ListPendingApprovals_Success(t *testing.T) {
	tenantID := shared.NewID()
	findingID := shared.NewID()
	requestedBy := shared.NewID()

	findingRepo := newMockFindingRepository()
	findingRepo.findings[findingID] = &vulnerability.Finding{}
	approvalRepo := newMockApprovalRepository()
	svc := newApprovalTestService(findingRepo, approvalRepo)

	// Create 3 pending approvals
	for i := 0; i < 3; i++ {
		_, err := svc.RequestApproval(context.Background(), app.RequestApprovalInput{
			TenantID:        tenantID.String(),
			FindingID:       findingID.String(),
			RequestedStatus: "false_positive",
			Justification:   "Test justification",
			RequestedBy:     requestedBy.String(),
		})
		require.NoError(t, err)
	}

	// Also create one in a different tenant (should not appear)
	otherTenantID := shared.NewID()
	otherFindingID := shared.NewID()
	findingRepo.findings[otherFindingID] = &vulnerability.Finding{}
	_, err := svc.RequestApproval(context.Background(), app.RequestApprovalInput{
		TenantID:        otherTenantID.String(),
		FindingID:       otherFindingID.String(),
		RequestedStatus: "accepted",
		Justification:   "Other tenant",
		RequestedBy:     requestedBy.String(),
	})
	require.NoError(t, err)

	result, err := svc.ListPendingApprovals(context.Background(), tenantID.String(), 1, 10)

	require.NoError(t, err)
	assert.Equal(t, int64(3), result.Total, "should only see approvals for the target tenant")
	assert.Len(t, result.Data, 3)
	assert.Equal(t, 1, result.Page)
	assert.Equal(t, 10, result.PerPage)
}

func TestFindingApprovalService_ListPendingApprovals_EmptyResult(t *testing.T) {
	tenantID := shared.NewID()

	findingRepo := newMockFindingRepository()
	approvalRepo := newMockApprovalRepository()
	svc := newApprovalTestService(findingRepo, approvalRepo)

	result, err := svc.ListPendingApprovals(context.Background(), tenantID.String(), 1, 10)

	require.NoError(t, err)
	assert.Equal(t, int64(0), result.Total)
	assert.Empty(t, result.Data)
}

func TestFindingApprovalService_ListPendingApprovals_InvalidTenantID(t *testing.T) {
	findingRepo := newMockFindingRepository()
	approvalRepo := newMockApprovalRepository()
	svc := newApprovalTestService(findingRepo, approvalRepo)

	_, err := svc.ListPendingApprovals(context.Background(), "not-a-uuid", 1, 10)

	assert.Error(t, err)
	assert.True(t, errors.Is(err, shared.ErrValidation))
}

// =============================================================================
// Tests: BulkUpdateFindingStatus
// =============================================================================

func TestFindingApprovalService_BulkUpdateFindingStatus_Success(t *testing.T) {
	tenantID := shared.NewID()
	findingIDs := []shared.ID{shared.NewID(), shared.NewID(), shared.NewID()}
	resolvedBy := shared.NewID()

	findingRepo := newMockFindingRepository()
	approvalRepo := newMockApprovalRepository()
	svc := newApprovalTestService(findingRepo, approvalRepo)

	err := svc.BulkUpdateFindingStatus(
		context.Background(),
		tenantID,
		findingIDs,
		vulnerability.FindingStatusResolved,
		"fixed_in_code",
		&resolvedBy,
	)

	require.NoError(t, err)

	// Verify the batch update was called
	require.Len(t, findingRepo.statusUpdates, 1)
	call := findingRepo.statusUpdates[0]
	assert.Equal(t, tenantID, call.TenantID)
	assert.Equal(t, findingIDs, call.IDs)
	assert.Equal(t, vulnerability.FindingStatusResolved, call.Status)
	assert.Equal(t, "fixed_in_code", call.Resolution)
	require.NotNil(t, call.ResolvedBy)
	assert.Equal(t, resolvedBy, *call.ResolvedBy)
}

func TestFindingApprovalService_BulkUpdateFindingStatus_RepoError(t *testing.T) {
	tenantID := shared.NewID()
	findingIDs := []shared.ID{shared.NewID()}
	resolvedBy := shared.NewID()

	findingRepo := newMockFindingRepository()
	findingRepo.statusBatchErr = errors.New("database error")
	approvalRepo := newMockApprovalRepository()
	svc := newApprovalTestService(findingRepo, approvalRepo)

	err := svc.BulkUpdateFindingStatus(
		context.Background(),
		tenantID,
		findingIDs,
		vulnerability.FindingStatusResolved,
		"",
		&resolvedBy,
	)

	assert.Error(t, err, "should propagate repository errors")
}

// =============================================================================
// Tests: ApprovalRepo not configured
// =============================================================================

func TestFindingApprovalService_ApprovalRepoNotConfigured(t *testing.T) {
	vulnRepo := &mockVulnerabilityRepository{}
	findingRepo := newMockFindingRepository()
	log := logger.NewNop()
	svc := app.NewVulnerabilityService(vulnRepo, findingRepo, log)
	// Deliberately NOT calling svc.SetApprovalRepository()

	t.Run("RequestApproval", func(t *testing.T) {
		_, err := svc.RequestApproval(context.Background(), app.RequestApprovalInput{
			TenantID:        shared.NewID().String(),
			FindingID:       shared.NewID().String(),
			RequestedStatus: "false_positive",
			Justification:   "Test",
			RequestedBy:     shared.NewID().String(),
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "approval workflow not configured")
	})

	t.Run("ApproveStatus", func(t *testing.T) {
		_, err := svc.ApproveStatus(context.Background(), app.ApproveStatusInput{
			TenantID:   shared.NewID().String(),
			ApprovalID: shared.NewID().String(),
			ApprovedBy: shared.NewID().String(),
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "approval workflow not configured")
	})

	t.Run("RejectApproval", func(t *testing.T) {
		_, err := svc.RejectApproval(context.Background(), app.RejectApprovalInput{
			TenantID:   shared.NewID().String(),
			ApprovalID: shared.NewID().String(),
			RejectedBy: shared.NewID().String(),
			Reason:     "Test",
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "approval workflow not configured")
	})

	t.Run("ListPendingApprovals", func(t *testing.T) {
		_, err := svc.ListPendingApprovals(context.Background(), shared.NewID().String(), 1, 10)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "approval workflow not configured")
	})

	t.Run("CancelApproval", func(t *testing.T) {
		_, err := svc.CancelApproval(context.Background(), app.CancelApprovalInput{
			TenantID:    shared.NewID().String(),
			ApprovalID:  shared.NewID().String(),
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
	findingRepo.findings[findingID] = &vulnerability.Finding{}
	approvalRepo := newMockApprovalRepository()
	svc := newApprovalTestService(findingRepo, approvalRepo)

	// Create approval
	created, err := svc.RequestApproval(context.Background(), app.RequestApprovalInput{
		TenantID:        tenantID.String(),
		FindingID:       findingID.String(),
		RequestedStatus: "false_positive",
		Justification:   "Test",
		RequestedBy:     requestedBy.String(),
	})
	require.NoError(t, err)

	// Cancel it (as the requester)
	approval, err := svc.CancelApproval(context.Background(), app.CancelApprovalInput{
		TenantID:    tenantID.String(),
		ApprovalID:  created.ID.String(),
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
	findingRepo.findings[findingID] = &vulnerability.Finding{}
	approvalRepo := newMockApprovalRepository()
	svc := newApprovalTestService(findingRepo, approvalRepo)

	// Create approval
	created, err := svc.RequestApproval(context.Background(), app.RequestApprovalInput{
		TenantID:        tenantID.String(),
		FindingID:       findingID.String(),
		RequestedStatus: "false_positive",
		Justification:   "Test",
		RequestedBy:     requestedBy.String(),
	})
	require.NoError(t, err)

	// Try to cancel as a different user
	approval, err := svc.CancelApproval(context.Background(), app.CancelApprovalInput{
		TenantID:    tenantID.String(),
		ApprovalID:  created.ID.String(),
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
	findingRepo.findings[findingID] = &vulnerability.Finding{}
	approvalRepo := newMockApprovalRepository()
	svc := newApprovalTestService(findingRepo, approvalRepo)

	// Create and approve
	created, err := svc.RequestApproval(context.Background(), app.RequestApprovalInput{
		TenantID:        tenantID.String(),
		FindingID:       findingID.String(),
		RequestedStatus: "false_positive",
		Justification:   "Test",
		RequestedBy:     requestedBy.String(),
	})
	require.NoError(t, err)

	_, err = svc.ApproveStatus(context.Background(), app.ApproveStatusInput{
		TenantID:   tenantID.String(),
		ApprovalID: created.ID.String(),
		ApprovedBy: approverID.String(),
	})
	require.NoError(t, err)

	// Try to cancel the already-approved approval
	approval, err := svc.CancelApproval(context.Background(), app.CancelApprovalInput{
		TenantID:    tenantID.String(),
		ApprovalID:  created.ID.String(),
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
	findingRepo.findings[findingID] = &vulnerability.Finding{}
	approvalRepo := newMockApprovalRepository()
	svc := newApprovalTestService(findingRepo, approvalRepo)

	input := app.RequestApprovalInput{
		TenantID:        tenantID.String(),
		FindingID:       findingID.String(),
		RequestedStatus: "invalid_garbage_status",
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
	findingRepo.findings[findingID] = &vulnerability.Finding{}
	approvalRepo := newMockApprovalRepository()
	svc := newApprovalTestService(findingRepo, approvalRepo)

	// Create approval
	created, err := svc.RequestApproval(context.Background(), app.RequestApprovalInput{
		TenantID:        tenantID.String(),
		FindingID:       findingID.String(),
		RequestedStatus: "false_positive",
		Justification:   "Test",
		RequestedBy:     requestedBy.String(),
	})
	require.NoError(t, err)

	// Set mock to return concurrent modification error on Update
	approvalRepo.updateErr = vulnerability.ErrConcurrentModification

	// Try to approve - should fail with concurrent modification
	approval, err := svc.ApproveStatus(context.Background(), app.ApproveStatusInput{
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

func (m *mockFindingRepository) BulkUpdateStatusByFilter(_ context.Context, _ shared.ID, _ vulnerability.FindingFilter, _ vulnerability.FindingStatus, _ string, _ *shared.ID) (int64, error) {
	return 0, nil
}

func (m *mockFindingRepository) FindRelatedCVEs(_ context.Context, _ shared.ID, _ string, _ vulnerability.FindingFilter) ([]vulnerability.RelatedCVE, error) {
	return nil, nil
}

func (m *mockFindingRepository) ListByStatusAndAssets(_ context.Context, _ shared.ID, _ vulnerability.FindingStatus, _ []shared.ID) ([]*vulnerability.Finding, error) {
	return nil, nil
}
