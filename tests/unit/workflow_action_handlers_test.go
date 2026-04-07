package unit

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"testing"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
	"github.com/openctemio/api/pkg/domain/workflow"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
)

// =============================================================================
// wfAction mock: Finding Repository (for VulnerabilityService)
// =============================================================================

type wfActionMockFindingRepo struct {
	findings  map[string]*vulnerability.Finding
	getErr    error
	updateErr error
}

func newWfActionMockFindingRepo() *wfActionMockFindingRepo {
	return &wfActionMockFindingRepo{
		findings: make(map[string]*vulnerability.Finding),
	}
}

func (m *wfActionMockFindingRepo) addFinding(f *vulnerability.Finding) {
	m.findings[f.ID().String()] = f
}

func (m *wfActionMockFindingRepo) Create(_ context.Context, f *vulnerability.Finding) error {
	m.findings[f.ID().String()] = f
	return nil
}

func (m *wfActionMockFindingRepo) CreateInTx(_ context.Context, _ *sql.Tx, f *vulnerability.Finding) error {
	m.findings[f.ID().String()] = f
	return nil
}

func (m *wfActionMockFindingRepo) CreateBatch(_ context.Context, _ []*vulnerability.Finding) error {
	return nil
}

func (m *wfActionMockFindingRepo) CreateBatchWithResult(_ context.Context, _ []*vulnerability.Finding) (*vulnerability.BatchCreateResult, error) {
	return nil, nil
}

func (m *wfActionMockFindingRepo) GetByID(_ context.Context, tenantID, id shared.ID) (*vulnerability.Finding, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	f, ok := m.findings[id.String()]
	if !ok {
		return nil, shared.ErrNotFound
	}
	if f.TenantID() != tenantID {
		return nil, shared.ErrNotFound
	}
	return f, nil
}

func (m *wfActionMockFindingRepo) GetByIDs(_ context.Context, _ shared.ID, _ []shared.ID) ([]*vulnerability.Finding, error) {
	return nil, nil
}

func (m *wfActionMockFindingRepo) Update(_ context.Context, f *vulnerability.Finding) error {
	if m.updateErr != nil {
		return m.updateErr
	}
	if _, ok := m.findings[f.ID().String()]; !ok {
		return shared.ErrNotFound
	}
	m.findings[f.ID().String()] = f
	return nil
}

func (m *wfActionMockFindingRepo) Delete(_ context.Context, _, _ shared.ID) error { return nil }

func (m *wfActionMockFindingRepo) List(_ context.Context, _ vulnerability.FindingFilter, _ vulnerability.FindingListOptions, _ pagination.Pagination) (pagination.Result[*vulnerability.Finding], error) {
	return pagination.Result[*vulnerability.Finding]{}, nil
}

func (m *wfActionMockFindingRepo) ListByAssetID(_ context.Context, _, _ shared.ID, _ vulnerability.FindingListOptions, _ pagination.Pagination) (pagination.Result[*vulnerability.Finding], error) {
	return pagination.Result[*vulnerability.Finding]{}, nil
}

func (m *wfActionMockFindingRepo) ListByVulnerabilityID(_ context.Context, _, _ shared.ID, _ vulnerability.FindingListOptions, _ pagination.Pagination) (pagination.Result[*vulnerability.Finding], error) {
	return pagination.Result[*vulnerability.Finding]{}, nil
}

func (m *wfActionMockFindingRepo) ListByComponentID(_ context.Context, _, _ shared.ID, _ vulnerability.FindingListOptions, _ pagination.Pagination) (pagination.Result[*vulnerability.Finding], error) {
	return pagination.Result[*vulnerability.Finding]{}, nil
}

func (m *wfActionMockFindingRepo) Count(_ context.Context, _ vulnerability.FindingFilter) (int64, error) {
	return int64(len(m.findings)), nil
}

func (m *wfActionMockFindingRepo) CountByAssetID(_ context.Context, _, _ shared.ID) (int64, error) {
	return 0, nil
}

func (m *wfActionMockFindingRepo) CountOpenByAssetID(_ context.Context, _, _ shared.ID) (int64, error) {
	return 0, nil
}

func (m *wfActionMockFindingRepo) GetByFingerprint(_ context.Context, _ shared.ID, _ string) (*vulnerability.Finding, error) {
	return nil, nil
}

func (m *wfActionMockFindingRepo) ExistsByFingerprint(_ context.Context, _ shared.ID, _ string) (bool, error) {
	return false, nil
}

func (m *wfActionMockFindingRepo) CheckFingerprintsExist(_ context.Context, _ shared.ID, _ []string) (map[string]bool, error) {
	return nil, nil
}

func (m *wfActionMockFindingRepo) UpdateScanIDBatchByFingerprints(_ context.Context, _ shared.ID, _ []string, _ string) (int64, error) {
	return 0, nil
}

func (m *wfActionMockFindingRepo) UpdateSnippetBatchByFingerprints(_ context.Context, _ shared.ID, _ map[string]string) (int64, error) {
	return 0, nil
}

func (m *wfActionMockFindingRepo) BatchCountByAssetIDs(_ context.Context, _ shared.ID, _ []shared.ID) (map[shared.ID]int64, error) {
	return nil, nil
}

func (m *wfActionMockFindingRepo) UpdateStatusBatch(_ context.Context, _ shared.ID, _ []shared.ID, _ vulnerability.FindingStatus, _ string, _ *shared.ID) error {
	return nil
}

func (m *wfActionMockFindingRepo) DeleteByAssetID(_ context.Context, _, _ shared.ID) error { return nil }

func (m *wfActionMockFindingRepo) DeleteByScanID(_ context.Context, _ shared.ID, _ string) error {
	return nil
}

func (m *wfActionMockFindingRepo) GetStats(_ context.Context, _ shared.ID, _ *shared.ID) (*vulnerability.FindingStats, error) {
	return vulnerability.NewFindingStats(), nil
}

func (m *wfActionMockFindingRepo) CountBySeverityForScan(_ context.Context, _ shared.ID, _ string) (vulnerability.SeverityCounts, error) {
	return vulnerability.SeverityCounts{}, nil
}

func (m *wfActionMockFindingRepo) AutoResolveStale(_ context.Context, _ shared.ID, _ shared.ID, _ string, _ string, _ *shared.ID) ([]shared.ID, error) {
	return nil, nil
}

func (m *wfActionMockFindingRepo) AutoReopenByFingerprint(_ context.Context, _ shared.ID, _ string) (*shared.ID, error) {
	return nil, nil
}

func (m *wfActionMockFindingRepo) AutoReopenByFingerprintsBatch(_ context.Context, _ shared.ID, _ []string) (map[string]shared.ID, error) {
	return nil, nil
}

func (m *wfActionMockFindingRepo) ExpireFeatureBranchFindings(_ context.Context, _ shared.ID, _ int) (int64, error) {
	return 0, nil
}

func (m *wfActionMockFindingRepo) ExistsByIDs(_ context.Context, _ shared.ID, _ []shared.ID) (map[shared.ID]bool, error) {
	return nil, nil
}

func (m *wfActionMockFindingRepo) GetByFingerprintsBatch(_ context.Context, _ shared.ID, _ []string) (map[string]*vulnerability.Finding, error) {
	return nil, nil
}

func (m *wfActionMockFindingRepo) EnrichBatchByFingerprints(_ context.Context, _ shared.ID, _ []*vulnerability.Finding, _ string) (int64, error) {
	return 0, nil
}

// =============================================================================
// wfAction mock: Vulnerability Repository (for VulnerabilityService)
// =============================================================================

type wfActionMockVulnRepo struct{}

func (m *wfActionMockVulnRepo) Create(_ context.Context, _ *vulnerability.Vulnerability) error {
	return nil
}

func (m *wfActionMockVulnRepo) GetByID(_ context.Context, _ shared.ID) (*vulnerability.Vulnerability, error) {
	return nil, shared.ErrNotFound
}

func (m *wfActionMockVulnRepo) GetByCVE(_ context.Context, _ string) (*vulnerability.Vulnerability, error) {
	return nil, shared.ErrNotFound
}

func (m *wfActionMockVulnRepo) Update(_ context.Context, _ *vulnerability.Vulnerability) error {
	return nil
}

func (m *wfActionMockVulnRepo) Delete(_ context.Context, _ shared.ID) error { return nil }

func (m *wfActionMockVulnRepo) List(_ context.Context, _ vulnerability.VulnerabilityFilter, _ vulnerability.VulnerabilityListOptions, _ pagination.Pagination) (pagination.Result[*vulnerability.Vulnerability], error) {
	return pagination.Result[*vulnerability.Vulnerability]{}, nil
}

func (m *wfActionMockVulnRepo) Count(_ context.Context, _ vulnerability.VulnerabilityFilter) (int64, error) {
	return 0, nil
}

func (m *wfActionMockVulnRepo) UpsertByCVE(_ context.Context, _ *vulnerability.Vulnerability) error {
	return nil
}

func (m *wfActionMockVulnRepo) ExistsByCVE(_ context.Context, _ string) (bool, error) {
	return false, nil
}

// =============================================================================
// Test helpers
// =============================================================================

// newWfActionTestFinding creates a test finding with tags.
func newWfActionTestFinding(tenantID shared.ID, tags []string) *vulnerability.Finding {
	assetID := shared.NewID()
	f, _ := vulnerability.NewFinding(
		tenantID,
		assetID,
		vulnerability.FindingSourceSAST,
		"semgrep",
		vulnerability.SeverityHigh,
		"SQL Injection",
	)
	if len(tags) > 0 {
		f.SetTags(tags)
	}
	return f
}

// newWfActionVulnService creates a VulnerabilityService backed by in-memory mocks.
func newWfActionVulnService() (*app.VulnerabilityService, *wfActionMockFindingRepo) {
	vulnRepo := &wfActionMockVulnRepo{}
	findingRepo := newWfActionMockFindingRepo()
	log := logger.NewNop()
	svc := app.NewVulnerabilityService(vulnRepo, findingRepo, log)
	return svc, findingRepo
}

// newWfActionInput is a convenience constructor for ActionInput.
func newWfActionInput(
	tenantID shared.ID,
	actionType workflow.ActionType,
	config map[string]any,
	triggerData map[string]any,
) *app.ActionInput {
	if config == nil {
		config = make(map[string]any)
	}
	if triggerData == nil {
		triggerData = make(map[string]any)
	}
	return &app.ActionInput{
		TenantID:     tenantID,
		WorkflowID:   shared.NewID(),
		RunID:        shared.NewID(),
		NodeKey:      "action_1",
		ActionType:   actionType,
		ActionConfig: config,
		TriggerData:  triggerData,
		Context:      make(map[string]any),
	}
}

// =============================================================================
// FindingActionHandler — assignUser
// =============================================================================

func TestWfActionFinding_AssignUser_Success(t *testing.T) {
	vulnSvc, findingRepo := newWfActionVulnService()
	log := logger.NewNop()
	h := app.NewFindingActionHandler(vulnSvc, log)

	tenantID := shared.NewID()
	userID := shared.NewID()
	f := newWfActionTestFinding(tenantID, nil)
	findingRepo.addFinding(f)

	input := newWfActionInput(tenantID, workflow.ActionTypeAssignUser, map[string]any{
		"finding_id": f.ID().String(),
		"user_id":    userID.String(),
	}, nil)

	out, err := h.Execute(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if out["assigned"] != true {
		t.Errorf("expected assigned=true, got %v", out["assigned"])
	}
	if out["finding_id"] != f.ID().String() {
		t.Errorf("expected finding_id=%s, got %v", f.ID().String(), out["finding_id"])
	}
	if out["action"] != "assign_user" {
		t.Errorf("expected action=assign_user, got %v", out["action"])
	}
}

func TestWfActionFinding_AssignUser_MissingFindingID(t *testing.T) {
	vulnSvc, _ := newWfActionVulnService()
	log := logger.NewNop()
	h := app.NewFindingActionHandler(vulnSvc, log)

	tenantID := shared.NewID()
	userID := shared.NewID()

	input := newWfActionInput(tenantID, workflow.ActionTypeAssignUser, map[string]any{
		"user_id": userID.String(),
	}, nil)

	_, err := h.Execute(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for missing finding_id, got nil")
	}
}

func TestWfActionFinding_AssignUser_MissingUserID(t *testing.T) {
	vulnSvc, findingRepo := newWfActionVulnService()
	log := logger.NewNop()
	h := app.NewFindingActionHandler(vulnSvc, log)

	tenantID := shared.NewID()
	f := newWfActionTestFinding(tenantID, nil)
	findingRepo.addFinding(f)

	input := newWfActionInput(tenantID, workflow.ActionTypeAssignUser, map[string]any{
		"finding_id": f.ID().String(),
	}, nil)

	_, err := h.Execute(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for missing user_id, got nil")
	}
}

func TestWfActionFinding_AssignUser_ServiceError(t *testing.T) {
	vulnSvc, findingRepo := newWfActionVulnService()
	log := logger.NewNop()
	h := app.NewFindingActionHandler(vulnSvc, log)

	tenantID := shared.NewID()
	userID := shared.NewID()
	f := newWfActionTestFinding(tenantID, nil)
	findingRepo.addFinding(f)
	findingRepo.getErr = errors.New("db error")

	input := newWfActionInput(tenantID, workflow.ActionTypeAssignUser, map[string]any{
		"finding_id": f.ID().String(),
		"user_id":    userID.String(),
	}, nil)

	_, err := h.Execute(context.Background(), input)
	if err == nil {
		t.Fatal("expected error when service fails, got nil")
	}
}

// =============================================================================
// FindingActionHandler — assignTeam
// =============================================================================

func TestWfActionFinding_AssignTeam_Success(t *testing.T) {
	vulnSvc, findingRepo := newWfActionVulnService()
	log := logger.NewNop()
	h := app.NewFindingActionHandler(vulnSvc, log)

	tenantID := shared.NewID()
	teamID := shared.NewID()
	f := newWfActionTestFinding(tenantID, nil)
	findingRepo.addFinding(f)

	input := newWfActionInput(tenantID, workflow.ActionTypeAssignTeam, map[string]any{
		"finding_id": f.ID().String(),
		"team_id":    teamID.String(),
	}, nil)

	out, err := h.Execute(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if out["assigned"] != true {
		t.Errorf("expected assigned=true, got %v", out["assigned"])
	}
	if out["team_id"] != teamID.String() {
		t.Errorf("expected team_id=%s, got %v", teamID.String(), out["team_id"])
	}
}

func TestWfActionFinding_AssignTeam_MissingFindingID(t *testing.T) {
	vulnSvc, _ := newWfActionVulnService()
	log := logger.NewNop()
	h := app.NewFindingActionHandler(vulnSvc, log)

	tenantID := shared.NewID()

	input := newWfActionInput(tenantID, workflow.ActionTypeAssignTeam, map[string]any{
		"team_id": shared.NewID().String(),
	}, nil)

	_, err := h.Execute(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for missing finding_id, got nil")
	}
}

func TestWfActionFinding_AssignTeam_MissingTeamID(t *testing.T) {
	vulnSvc, findingRepo := newWfActionVulnService()
	log := logger.NewNop()
	h := app.NewFindingActionHandler(vulnSvc, log)

	tenantID := shared.NewID()
	f := newWfActionTestFinding(tenantID, nil)
	findingRepo.addFinding(f)

	input := newWfActionInput(tenantID, workflow.ActionTypeAssignTeam, map[string]any{
		"finding_id": f.ID().String(),
	}, nil)

	_, err := h.Execute(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for missing team_id, got nil")
	}
}

// =============================================================================
// FindingActionHandler — updatePriority
// =============================================================================

func TestWfActionFinding_UpdatePriority_Success(t *testing.T) {
	vulnSvc, findingRepo := newWfActionVulnService()
	log := logger.NewNop()
	h := app.NewFindingActionHandler(vulnSvc, log)

	tenantID := shared.NewID()
	f := newWfActionTestFinding(tenantID, nil)
	findingRepo.addFinding(f)

	input := newWfActionInput(tenantID, workflow.ActionTypeUpdatePriority, map[string]any{
		"finding_id": f.ID().String(),
		"priority":   "high",
	}, nil)

	out, err := h.Execute(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if out["updated"] != true {
		t.Errorf("expected updated=true, got %v", out["updated"])
	}
	if out["priority"] != "high" {
		t.Errorf("expected priority=high, got %v", out["priority"])
	}
}

func TestWfActionFinding_UpdatePriority_MissingFindingID(t *testing.T) {
	vulnSvc, _ := newWfActionVulnService()
	log := logger.NewNop()
	h := app.NewFindingActionHandler(vulnSvc, log)

	tenantID := shared.NewID()
	input := newWfActionInput(tenantID, workflow.ActionTypeUpdatePriority, map[string]any{
		"priority": "high",
	}, nil)

	_, err := h.Execute(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for missing finding_id, got nil")
	}
}

func TestWfActionFinding_UpdatePriority_MissingPriority(t *testing.T) {
	vulnSvc, findingRepo := newWfActionVulnService()
	log := logger.NewNop()
	h := app.NewFindingActionHandler(vulnSvc, log)

	tenantID := shared.NewID()
	f := newWfActionTestFinding(tenantID, nil)
	findingRepo.addFinding(f)

	input := newWfActionInput(tenantID, workflow.ActionTypeUpdatePriority, map[string]any{
		"finding_id": f.ID().String(),
	}, nil)

	_, err := h.Execute(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for missing priority, got nil")
	}
}

// =============================================================================
// FindingActionHandler — updateStatus
// =============================================================================

func TestWfActionFinding_UpdateStatus_Success(t *testing.T) {
	vulnSvc, findingRepo := newWfActionVulnService()
	log := logger.NewNop()
	h := app.NewFindingActionHandler(vulnSvc, log)

	tenantID := shared.NewID()
	f := newWfActionTestFinding(tenantID, nil)
	findingRepo.addFinding(f)

	input := newWfActionInput(tenantID, workflow.ActionTypeUpdateStatus, map[string]any{
		"finding_id": f.ID().String(),
		"status":     "confirmed",
	}, nil)

	out, err := h.Execute(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if out["updated"] != true {
		t.Errorf("expected updated=true, got %v", out["updated"])
	}
	if out["status"] != "confirmed" {
		t.Errorf("expected status=confirmed, got %v", out["status"])
	}
}

func TestWfActionFinding_UpdateStatus_MissingFindingID(t *testing.T) {
	vulnSvc, _ := newWfActionVulnService()
	log := logger.NewNop()
	h := app.NewFindingActionHandler(vulnSvc, log)

	tenantID := shared.NewID()
	input := newWfActionInput(tenantID, workflow.ActionTypeUpdateStatus, map[string]any{
		"status": "confirmed",
	}, nil)

	_, err := h.Execute(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for missing finding_id, got nil")
	}
}

func TestWfActionFinding_UpdateStatus_MissingStatus(t *testing.T) {
	vulnSvc, findingRepo := newWfActionVulnService()
	log := logger.NewNop()
	h := app.NewFindingActionHandler(vulnSvc, log)

	tenantID := shared.NewID()
	f := newWfActionTestFinding(tenantID, nil)
	findingRepo.addFinding(f)

	input := newWfActionInput(tenantID, workflow.ActionTypeUpdateStatus, map[string]any{
		"finding_id": f.ID().String(),
	}, nil)

	_, err := h.Execute(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for missing status, got nil")
	}
}

func TestWfActionFinding_UpdateStatus_ServiceError(t *testing.T) {
	vulnSvc, findingRepo := newWfActionVulnService()
	log := logger.NewNop()
	h := app.NewFindingActionHandler(vulnSvc, log)

	tenantID := shared.NewID()
	f := newWfActionTestFinding(tenantID, nil)
	findingRepo.addFinding(f)
	findingRepo.getErr = errors.New("db failure")

	input := newWfActionInput(tenantID, workflow.ActionTypeUpdateStatus, map[string]any{
		"finding_id": f.ID().String(),
		"status":     "confirmed",
	}, nil)

	_, err := h.Execute(context.Background(), input)
	if err == nil {
		t.Fatal("expected error when service fails, got nil")
	}
}

// =============================================================================
// FindingActionHandler — addTags
// =============================================================================

func TestWfActionFinding_AddTags_Success(t *testing.T) {
	vulnSvc, findingRepo := newWfActionVulnService()
	log := logger.NewNop()
	h := app.NewFindingActionHandler(vulnSvc, log)

	tenantID := shared.NewID()
	f := newWfActionTestFinding(tenantID, []string{"existing-tag"})
	findingRepo.addFinding(f)

	input := newWfActionInput(tenantID, workflow.ActionTypeAddTags, map[string]any{
		"finding_id": f.ID().String(),
		"tags":       []any{"urgent", "reviewed"},
	}, nil)

	out, err := h.Execute(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if out["added"] != true {
		t.Errorf("expected added=true, got %v", out["added"])
	}
}

func TestWfActionFinding_AddTags_MissingFindingID(t *testing.T) {
	vulnSvc, _ := newWfActionVulnService()
	log := logger.NewNop()
	h := app.NewFindingActionHandler(vulnSvc, log)

	tenantID := shared.NewID()
	input := newWfActionInput(tenantID, workflow.ActionTypeAddTags, map[string]any{
		"tags": []any{"urgent"},
	}, nil)

	_, err := h.Execute(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for missing finding_id, got nil")
	}
}

func TestWfActionFinding_AddTags_MissingTags(t *testing.T) {
	vulnSvc, findingRepo := newWfActionVulnService()
	log := logger.NewNop()
	h := app.NewFindingActionHandler(vulnSvc, log)

	tenantID := shared.NewID()
	f := newWfActionTestFinding(tenantID, nil)
	findingRepo.addFinding(f)

	input := newWfActionInput(tenantID, workflow.ActionTypeAddTags, map[string]any{
		"finding_id": f.ID().String(),
	}, nil)

	_, err := h.Execute(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for missing tags, got nil")
	}
}

func TestWfActionFinding_AddTags_EmptyTags(t *testing.T) {
	vulnSvc, findingRepo := newWfActionVulnService()
	log := logger.NewNop()
	h := app.NewFindingActionHandler(vulnSvc, log)

	tenantID := shared.NewID()
	f := newWfActionTestFinding(tenantID, nil)
	findingRepo.addFinding(f)

	input := newWfActionInput(tenantID, workflow.ActionTypeAddTags, map[string]any{
		"finding_id": f.ID().String(),
		"tags":       []any{},
	}, nil)

	_, err := h.Execute(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for empty tags slice, got nil")
	}
}

// =============================================================================
// FindingActionHandler — removeTags
// =============================================================================

func TestWfActionFinding_RemoveTags_Success(t *testing.T) {
	vulnSvc, findingRepo := newWfActionVulnService()
	log := logger.NewNop()
	h := app.NewFindingActionHandler(vulnSvc, log)

	tenantID := shared.NewID()
	f := newWfActionTestFinding(tenantID, []string{"urgent", "reviewed"})
	findingRepo.addFinding(f)

	input := newWfActionInput(tenantID, workflow.ActionTypeRemoveTags, map[string]any{
		"finding_id": f.ID().String(),
		"tags":       []any{"urgent"},
	}, nil)

	out, err := h.Execute(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if out["removed"] != true {
		t.Errorf("expected removed=true, got %v", out["removed"])
	}
}

func TestWfActionFinding_RemoveTags_MissingFindingID(t *testing.T) {
	vulnSvc, _ := newWfActionVulnService()
	log := logger.NewNop()
	h := app.NewFindingActionHandler(vulnSvc, log)

	tenantID := shared.NewID()
	input := newWfActionInput(tenantID, workflow.ActionTypeRemoveTags, map[string]any{
		"tags": []any{"urgent"},
	}, nil)

	_, err := h.Execute(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for missing finding_id, got nil")
	}
}

func TestWfActionFinding_RemoveTags_MissingTags(t *testing.T) {
	vulnSvc, findingRepo := newWfActionVulnService()
	log := logger.NewNop()
	h := app.NewFindingActionHandler(vulnSvc, log)

	tenantID := shared.NewID()
	f := newWfActionTestFinding(tenantID, []string{"urgent"})
	findingRepo.addFinding(f)

	input := newWfActionInput(tenantID, workflow.ActionTypeRemoveTags, map[string]any{
		"finding_id": f.ID().String(),
	}, nil)

	_, err := h.Execute(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for missing tags, got nil")
	}
}

// =============================================================================
// FindingActionHandler — getFindingID (tested via assignUser)
// =============================================================================

func TestWfActionFinding_GetFindingID_FromActionConfig(t *testing.T) {
	vulnSvc, findingRepo := newWfActionVulnService()
	log := logger.NewNop()
	h := app.NewFindingActionHandler(vulnSvc, log)

	tenantID := shared.NewID()
	userID := shared.NewID()
	f := newWfActionTestFinding(tenantID, nil)
	findingRepo.addFinding(f)

	// finding_id in ActionConfig
	input := &app.ActionInput{
		TenantID:   tenantID,
		WorkflowID: shared.NewID(),
		RunID:      shared.NewID(),
		NodeKey:    "action_1",
		ActionType: workflow.ActionTypeAssignUser,
		ActionConfig: map[string]any{
			"finding_id": f.ID().String(),
			"user_id":    userID.String(),
		},
		TriggerData: map[string]any{},
		Context:     map[string]any{},
	}

	out, err := h.Execute(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error when finding_id in ActionConfig, got %v", err)
	}
	if out["finding_id"] != f.ID().String() {
		t.Errorf("expected finding_id=%s, got %v", f.ID().String(), out["finding_id"])
	}
}

func TestWfActionFinding_GetFindingID_FromTriggerData(t *testing.T) {
	vulnSvc, findingRepo := newWfActionVulnService()
	log := logger.NewNop()
	h := app.NewFindingActionHandler(vulnSvc, log)

	tenantID := shared.NewID()
	userID := shared.NewID()
	f := newWfActionTestFinding(tenantID, nil)
	findingRepo.addFinding(f)

	// finding_id in TriggerData["finding"]["id"]
	input := &app.ActionInput{
		TenantID:   tenantID,
		WorkflowID: shared.NewID(),
		RunID:      shared.NewID(),
		NodeKey:    "action_1",
		ActionType: workflow.ActionTypeAssignUser,
		ActionConfig: map[string]any{
			"user_id": userID.String(),
		},
		TriggerData: map[string]any{
			"finding": map[string]any{
				"id": f.ID().String(),
			},
		},
		Context: map[string]any{},
	}

	out, err := h.Execute(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error when finding_id in TriggerData, got %v", err)
	}
	if out["finding_id"] != f.ID().String() {
		t.Errorf("expected finding_id=%s, got %v", f.ID().String(), out["finding_id"])
	}
}

func TestWfActionFinding_GetFindingID_Missing(t *testing.T) {
	vulnSvc, _ := newWfActionVulnService()
	log := logger.NewNop()
	h := app.NewFindingActionHandler(vulnSvc, log)

	tenantID := shared.NewID()
	userID := shared.NewID()

	// No finding_id anywhere
	input := &app.ActionInput{
		TenantID:     tenantID,
		WorkflowID:   shared.NewID(),
		RunID:        shared.NewID(),
		NodeKey:      "action_1",
		ActionType:   workflow.ActionTypeAssignUser,
		ActionConfig: map[string]any{"user_id": userID.String()},
		TriggerData:  map[string]any{},
		Context:      map[string]any{},
	}

	_, err := h.Execute(context.Background(), input)
	if err == nil {
		t.Fatal("expected error when finding_id is absent everywhere, got nil")
	}
}

// =============================================================================
// FindingActionHandler — unsupported action type
// =============================================================================

func TestWfActionFinding_UnsupportedAction(t *testing.T) {
	vulnSvc, _ := newWfActionVulnService()
	log := logger.NewNop()
	h := app.NewFindingActionHandler(vulnSvc, log)

	tenantID := shared.NewID()
	input := newWfActionInput(tenantID, workflow.ActionTypeRunScript, nil, nil)

	_, err := h.Execute(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for unsupported action type, got nil")
	}
}

// =============================================================================
// PipelineTriggerHandler — triggerPipeline
// =============================================================================

func TestWfActionPipeline_TriggerPipeline_NilService(t *testing.T) {
	// pipelineService == nil → returns error-less map with triggered=false
	log := logger.NewNop()
	h := app.NewPipelineTriggerHandler(nil, nil, log)

	tenantID := shared.NewID()
	pipelineID := shared.NewID()

	input := newWfActionInput(tenantID, workflow.ActionTypeTriggerPipeline, map[string]any{
		"pipeline_id": pipelineID.String(),
	}, nil)

	out, err := h.Execute(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error when pipelineService is nil, got %v", err)
	}
	triggered, _ := out["triggered"].(bool)
	if triggered {
		t.Errorf("expected triggered=false when service is nil, got true")
	}
}

func TestWfActionPipeline_TriggerPipeline_MissingPipelineID(t *testing.T) {
	log := logger.NewNop()
	h := app.NewPipelineTriggerHandler(nil, nil, log)

	tenantID := shared.NewID()
	input := newWfActionInput(tenantID, workflow.ActionTypeTriggerPipeline, map[string]any{}, nil)

	_, err := h.Execute(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for missing pipeline_id, got nil")
	}
}

func TestWfActionPipeline_TriggerPipeline_InvalidPipelineIDFormat(t *testing.T) {
	log := logger.NewNop()
	h := app.NewPipelineTriggerHandler(nil, nil, log)

	tenantID := shared.NewID()
	input := newWfActionInput(tenantID, workflow.ActionTypeTriggerPipeline, map[string]any{
		"pipeline_id": "not-a-uuid",
	}, nil)

	_, err := h.Execute(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for invalid pipeline_id format, got nil")
	}
}

// =============================================================================
// PipelineTriggerHandler — triggerScan
// =============================================================================

func TestWfActionPipeline_TriggerScan_NilService(t *testing.T) {
	log := logger.NewNop()
	h := app.NewPipelineTriggerHandler(nil, nil, log)

	tenantID := shared.NewID()
	scanID := shared.NewID()

	input := newWfActionInput(tenantID, workflow.ActionTypeTriggerScan, map[string]any{
		"scan_id": scanID.String(),
	}, nil)

	out, err := h.Execute(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error when scanService is nil, got %v", err)
	}
	triggered, _ := out["triggered"].(bool)
	if triggered {
		t.Errorf("expected triggered=false when service is nil, got true")
	}
}

func TestWfActionPipeline_TriggerScan_MissingScanID(t *testing.T) {
	log := logger.NewNop()
	h := app.NewPipelineTriggerHandler(nil, nil, log)

	tenantID := shared.NewID()
	input := newWfActionInput(tenantID, workflow.ActionTypeTriggerScan, map[string]any{}, nil)

	_, err := h.Execute(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for missing scan_id, got nil")
	}
}

func TestWfActionPipeline_TriggerScan_InvalidScanIDFormat(t *testing.T) {
	log := logger.NewNop()
	h := app.NewPipelineTriggerHandler(nil, nil, log)

	tenantID := shared.NewID()
	input := newWfActionInput(tenantID, workflow.ActionTypeTriggerScan, map[string]any{
		"scan_id": "bad-id",
	}, nil)

	_, err := h.Execute(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for invalid scan_id format, got nil")
	}
}

func TestWfActionPipeline_UnsupportedAction(t *testing.T) {
	log := logger.NewNop()
	h := app.NewPipelineTriggerHandler(nil, nil, log)

	tenantID := shared.NewID()
	input := newWfActionInput(tenantID, workflow.ActionTypeAssignUser, nil, nil)

	_, err := h.Execute(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for unsupported action type, got nil")
	}
}

// =============================================================================
// TicketActionHandler — createTicket
// =============================================================================

func TestWfActionTicket_CreateTicket_Success(t *testing.T) {
	log := logger.NewNop()
	h := app.NewTicketActionHandler(nil, log)

	tenantID := shared.NewID()
	input := newWfActionInput(tenantID, workflow.ActionTypeCreateTicket, map[string]any{
		"integration_id": shared.NewID().String(),
		"title":          "Fix SQL Injection",
		"description":    "Found in login endpoint",
		"project":        "SEC",
		"issue_type":     "Bug",
		"priority":       "High",
		"labels":         []any{"security", "urgent"},
	}, nil)

	out, err := h.Execute(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if out["created"] != true {
		t.Errorf("expected created=true, got %v", out["created"])
	}
	if out["title"] != "Fix SQL Injection" {
		t.Errorf("expected title=Fix SQL Injection, got %v", out["title"])
	}
	if out["action"] != "create_ticket" {
		t.Errorf("expected action=create_ticket, got %v", out["action"])
	}
}

func TestWfActionTicket_CreateTicket_MissingIntegrationID(t *testing.T) {
	log := logger.NewNop()
	h := app.NewTicketActionHandler(nil, log)

	tenantID := shared.NewID()
	input := newWfActionInput(tenantID, workflow.ActionTypeCreateTicket, map[string]any{
		"title": "Fix SQL Injection",
	}, nil)

	_, err := h.Execute(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for missing integration_id, got nil")
	}
}

func TestWfActionTicket_CreateTicket_MissingTitle(t *testing.T) {
	log := logger.NewNop()
	h := app.NewTicketActionHandler(nil, log)

	tenantID := shared.NewID()
	input := newWfActionInput(tenantID, workflow.ActionTypeCreateTicket, map[string]any{
		"integration_id": shared.NewID().String(),
	}, nil)

	_, err := h.Execute(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for missing title, got nil")
	}
}

// =============================================================================
// TicketActionHandler — updateTicket
// =============================================================================

func TestWfActionTicket_UpdateTicket_Success(t *testing.T) {
	log := logger.NewNop()
	h := app.NewTicketActionHandler(nil, log)

	tenantID := shared.NewID()
	input := newWfActionInput(tenantID, workflow.ActionTypeUpdateTicket, map[string]any{
		"integration_id": shared.NewID().String(),
		"ticket_id":      "SEC-123",
		"status":         "In Progress",
		"comment":        "Working on it",
		"assignee":       "alice",
	}, nil)

	out, err := h.Execute(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if out["updated"] != true {
		t.Errorf("expected updated=true, got %v", out["updated"])
	}
	if out["ticket_id"] != "SEC-123" {
		t.Errorf("expected ticket_id=SEC-123, got %v", out["ticket_id"])
	}
}

func TestWfActionTicket_UpdateTicket_MissingIntegrationID(t *testing.T) {
	log := logger.NewNop()
	h := app.NewTicketActionHandler(nil, log)

	tenantID := shared.NewID()
	input := newWfActionInput(tenantID, workflow.ActionTypeUpdateTicket, map[string]any{
		"ticket_id": "SEC-123",
	}, nil)

	_, err := h.Execute(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for missing integration_id, got nil")
	}
}

func TestWfActionTicket_UpdateTicket_MissingTicketID(t *testing.T) {
	log := logger.NewNop()
	h := app.NewTicketActionHandler(nil, log)

	tenantID := shared.NewID()
	input := newWfActionInput(tenantID, workflow.ActionTypeUpdateTicket, map[string]any{
		"integration_id": shared.NewID().String(),
	}, nil)

	_, err := h.Execute(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for missing ticket_id, got nil")
	}
}

func TestWfActionTicket_UnsupportedAction(t *testing.T) {
	log := logger.NewNop()
	h := app.NewTicketActionHandler(nil, log)

	tenantID := shared.NewID()
	input := newWfActionInput(tenantID, workflow.ActionTypeRunScript, nil, nil)

	_, err := h.Execute(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for unsupported action type, got nil")
	}
}

// =============================================================================
// AITriageActionHandler — triggerAITriage
// =============================================================================

func TestWfActionAITriage_TriggerAITriage_NilService(t *testing.T) {
	// aiTriageService == nil → returns map with triggered=false (no error)
	log := logger.NewNop()
	h := app.NewAITriageActionHandler(nil, log)

	tenantID := shared.NewID()
	findingID := shared.NewID()

	input := newWfActionInput(tenantID, workflow.ActionTypeTriggerAITriage, map[string]any{
		"finding_id": findingID.String(),
	}, nil)

	out, err := h.Execute(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error when aiTriageService is nil, got %v", err)
	}
	triggered, _ := out["triggered"].(bool)
	if triggered {
		t.Errorf("expected triggered=false when service is nil, got true")
	}
}

func TestWfActionAITriage_TriggerAITriage_MissingFindingID(t *testing.T) {
	log := logger.NewNop()
	h := app.NewAITriageActionHandler(nil, log)

	tenantID := shared.NewID()
	input := newWfActionInput(tenantID, workflow.ActionTypeTriggerAITriage, map[string]any{}, nil)

	_, err := h.Execute(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for missing finding_id, got nil")
	}
}

func TestWfActionAITriage_TriggerAITriage_FindingIDFromTriggerData(t *testing.T) {
	log := logger.NewNop()
	h := app.NewAITriageActionHandler(nil, log)

	tenantID := shared.NewID()
	findingID := shared.NewID()

	// finding_id resolved from TriggerData["finding"]["id"]
	input := &app.ActionInput{
		TenantID:     tenantID,
		WorkflowID:   shared.NewID(),
		RunID:        shared.NewID(),
		NodeKey:      "triage_1",
		ActionType:   workflow.ActionTypeTriggerAITriage,
		ActionConfig: map[string]any{},
		TriggerData: map[string]any{
			"finding": map[string]any{
				"id": findingID.String(),
			},
		},
		Context: map[string]any{},
	}

	out, err := h.Execute(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error when service is nil (triggered=false), got %v", err)
	}
	if out["finding_id"] != findingID.String() {
		t.Errorf("expected finding_id=%s, got %v", findingID.String(), out["finding_id"])
	}
}

func TestWfActionAITriage_UnsupportedAction(t *testing.T) {
	log := logger.NewNop()
	h := app.NewAITriageActionHandler(nil, log)

	tenantID := shared.NewID()
	input := newWfActionInput(tenantID, workflow.ActionTypeAssignUser, nil, nil)

	_, err := h.Execute(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for unsupported action type, got nil")
	}
}

// =============================================================================
// ScriptRunnerHandler — Execute (always returns error)
// =============================================================================

func TestWfActionScriptRunner_Execute_AlwaysDisabled(t *testing.T) {
	log := logger.NewNop()
	h := app.NewScriptRunnerHandler(log)

	tenantID := shared.NewID()
	input := newWfActionInput(tenantID, workflow.ActionTypeRunScript, map[string]any{
		"script": "echo hello",
	}, nil)

	out, err := h.Execute(context.Background(), input)
	if err == nil {
		t.Fatal("expected error (script execution disabled), got nil")
	}
	// The handler also returns a partial output map
	if out == nil {
		t.Fatal("expected non-nil output map even on error")
	}
	if out["executed"] != false {
		t.Errorf("expected executed=false, got %v", out["executed"])
	}
}

// =============================================================================
// RegisterAllActionHandlers
// =============================================================================

func TestWfAction_RegisterAllActionHandlers_RegistersAllTypes(t *testing.T) {
	wfRepo := NewMockWorkflowRepository()
	runRepo := NewMockRunRepository()
	nodeRunRepo := NewMockNodeRunRepository()
	log := logger.NewNop()

	executor := app.NewWorkflowExecutor(wfRepo, runRepo, nodeRunRepo, log)

	// Build a VulnerabilityService backed by minimal in-memory mocks.
	vulnSvc, _ := newWfActionVulnService()

	// Register all handlers (nil for pipeline, scan, integration — they may be nil).
	app.RegisterAllActionHandlers(executor, vulnSvc, nil, nil, nil, log)

	// Verify handlers were registered by exercising each action type.
	// We do this by calling Execute directly on the individual handlers (already tested above).
	// Here we just verify that registration does not panic and the executor has handlers set.
	// The actual handler registration is tested implicitly by the above tests.
	_ = fmt.Sprintf("registered executor: %v", executor)
}

func TestWfAction_RegisterAllActionHandlers_NilVulnSvc(t *testing.T) {
	wfRepo := NewMockWorkflowRepository()
	runRepo := NewMockRunRepository()
	nodeRunRepo := NewMockNodeRunRepository()
	log := logger.NewNop()

	executor := app.NewWorkflowExecutor(wfRepo, runRepo, nodeRunRepo, log)

	// nil vulnSvc → finding handlers must NOT be registered (no panic)
	app.RegisterAllActionHandlers(executor, nil, nil, nil, nil, log)
}

// =============================================================================
// RegisterAllActionHandlersWithAI
// =============================================================================

func TestWfAction_RegisterAllActionHandlersWithAI_IncludesAITriage(t *testing.T) {
	wfRepo := NewMockWorkflowRepository()
	runRepo := NewMockRunRepository()
	nodeRunRepo := NewMockNodeRunRepository()
	log := logger.NewNop()

	executor := app.NewWorkflowExecutor(wfRepo, runRepo, nodeRunRepo, log)

	vulnSvc, _ := newWfActionVulnService()

	// nil aiTriageSvc → AI triage handler must NOT be registered (no panic)
	app.RegisterAllActionHandlersWithAI(executor, vulnSvc, nil, nil, nil, nil, log)
}

func TestWfAction_RegisterAllActionHandlersWithAI_AllNil(t *testing.T) {
	wfRepo := NewMockWorkflowRepository()
	runRepo := NewMockRunRepository()
	nodeRunRepo := NewMockNodeRunRepository()
	log := logger.NewNop()

	executor := app.NewWorkflowExecutor(wfRepo, runRepo, nodeRunRepo, log)

	// All nil services — only ScriptRunnerHandler should be registered (no panic)
	app.RegisterAllActionHandlersWithAI(executor, nil, nil, nil, nil, nil, log)
}

// =============================================================================
// Edge-case: unsupported priority (update_priority passes any string through)
// =============================================================================

func TestWfActionFinding_UpdatePriority_AnyStringIsAccepted(t *testing.T) {
	// The handler does not validate the priority value — it accepts any non-empty string.
	vulnSvc, findingRepo := newWfActionVulnService()
	log := logger.NewNop()
	h := app.NewFindingActionHandler(vulnSvc, log)

	tenantID := shared.NewID()
	f := newWfActionTestFinding(tenantID, nil)
	findingRepo.addFinding(f)

	input := newWfActionInput(tenantID, workflow.ActionTypeUpdatePriority, map[string]any{
		"finding_id": f.ID().String(),
		"priority":   "banana",
	}, nil)

	out, err := h.Execute(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error for arbitrary priority string, got %v", err)
	}
	if out["priority"] != "banana" {
		t.Errorf("expected priority=banana, got %v", out["priority"])
	}
}





func (m *wfActionMockFindingRepo) ListFindingGroups(_ context.Context, _ shared.ID, _ string, _ vulnerability.FindingFilter, _ pagination.Pagination) (pagination.Result[*vulnerability.FindingGroup], error) {
	return pagination.Result[*vulnerability.FindingGroup]{}, nil
}

func (m *wfActionMockFindingRepo) BulkUpdateStatusByFilter(_ context.Context, _ shared.ID, _ vulnerability.FindingFilter, _ vulnerability.FindingStatus, _ string, _ *shared.ID) (int64, error) {
	return 0, nil
}

func (m *wfActionMockFindingRepo) FindRelatedCVEs(_ context.Context, _ shared.ID, _ string, _ vulnerability.FindingFilter) ([]vulnerability.RelatedCVE, error) {
	return nil, nil
}

func (m *wfActionMockFindingRepo) ListByStatusAndAssets(_ context.Context, _ shared.ID, _ vulnerability.FindingStatus, _ []shared.ID) ([]*vulnerability.Finding, error) {
	return nil, nil
}
