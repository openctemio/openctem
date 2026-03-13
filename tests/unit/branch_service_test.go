package unit

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/pkg/domain/branch"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
)

// ============================================================================
// Mock Repository
// ============================================================================

// branchSvcMockRepository implements branch.Repository for testing.
type branchSvcMockRepository struct {
	branches       map[string]*branch.Branch
	createErr      error
	updateErr      error
	deleteErr      error
	listErr        error
	listByRepoErr  error
	countErr       error
	existsByNameFn func(ctx context.Context, repositoryID shared.ID, name string) (bool, error)
	defaultBranch  *branch.Branch
	defaultErr     error
	setDefaultErr  error
}

func newBranchSvcMockRepository() *branchSvcMockRepository {
	return &branchSvcMockRepository{
		branches: make(map[string]*branch.Branch),
	}
}

func (m *branchSvcMockRepository) Create(_ context.Context, b *branch.Branch) error {
	if m.createErr != nil {
		return m.createErr
	}
	m.branches[b.ID().String()] = b
	return nil
}

func (m *branchSvcMockRepository) GetByID(_ context.Context, id shared.ID) (*branch.Branch, error) {
	b, ok := m.branches[id.String()]
	if !ok {
		return nil, branch.ErrNotFound
	}
	return b, nil
}

func (m *branchSvcMockRepository) GetByName(_ context.Context, repositoryID shared.ID, name string) (*branch.Branch, error) {
	for _, b := range m.branches {
		if b.RepositoryID() == repositoryID && b.Name() == name {
			return b, nil
		}
	}
	return nil, branch.ErrNotFound
}

func (m *branchSvcMockRepository) Update(_ context.Context, b *branch.Branch) error {
	if m.updateErr != nil {
		return m.updateErr
	}
	m.branches[b.ID().String()] = b
	return nil
}

func (m *branchSvcMockRepository) Delete(_ context.Context, id shared.ID) error {
	if m.deleteErr != nil {
		return m.deleteErr
	}
	delete(m.branches, id.String())
	return nil
}

func (m *branchSvcMockRepository) List(_ context.Context, filter branch.Filter, _ branch.ListOptions, page pagination.Pagination) (pagination.Result[*branch.Branch], error) {
	if m.listErr != nil {
		return pagination.Result[*branch.Branch]{}, m.listErr
	}
	result := make([]*branch.Branch, 0, len(m.branches))
	for _, b := range m.branches {
		if filter.RepositoryID != nil && b.RepositoryID() != *filter.RepositoryID {
			continue
		}
		result = append(result, b)
	}
	total := int64(len(result))
	return pagination.Result[*branch.Branch]{
		Data:       result,
		Total:      total,
		Page:       page.Page,
		PerPage:    page.PerPage,
		TotalPages: int((total + int64(page.PerPage) - 1) / int64(page.PerPage)),
	}, nil
}

func (m *branchSvcMockRepository) ListByRepository(_ context.Context, repositoryID shared.ID) ([]*branch.Branch, error) {
	if m.listByRepoErr != nil {
		return nil, m.listByRepoErr
	}
	result := make([]*branch.Branch, 0)
	for _, b := range m.branches {
		if b.RepositoryID() == repositoryID {
			result = append(result, b)
		}
	}
	return result, nil
}

func (m *branchSvcMockRepository) GetDefaultBranch(_ context.Context, _ shared.ID) (*branch.Branch, error) {
	if m.defaultErr != nil {
		return nil, m.defaultErr
	}
	if m.defaultBranch != nil {
		return m.defaultBranch, nil
	}
	return nil, branch.ErrNotFound
}

func (m *branchSvcMockRepository) SetDefaultBranch(_ context.Context, _ shared.ID, branchID shared.ID) error {
	if m.setDefaultErr != nil {
		return m.setDefaultErr
	}
	// Simulate clearing old default and setting new
	for _, b := range m.branches {
		b.SetDefault(false)
	}
	if b, ok := m.branches[branchID.String()]; ok {
		b.SetDefault(true)
	}
	return nil
}

func (m *branchSvcMockRepository) Count(_ context.Context, filter branch.Filter) (int64, error) {
	if m.countErr != nil {
		return 0, m.countErr
	}
	var count int64
	for _, b := range m.branches {
		if filter.RepositoryID != nil && b.RepositoryID() != *filter.RepositoryID {
			continue
		}
		count++
	}
	return count, nil
}

func (m *branchSvcMockRepository) ExistsByName(_ context.Context, repositoryID shared.ID, name string) (bool, error) {
	if m.existsByNameFn != nil {
		return m.existsByNameFn(context.Background(), repositoryID, name)
	}
	for _, b := range m.branches {
		if b.RepositoryID() == repositoryID && b.Name() == name {
			return true, nil
		}
	}
	return false, nil
}

// ============================================================================
// Helper Functions
// ============================================================================

func newTestBranchService() (*app.BranchService, *branchSvcMockRepository) {
	repo := newBranchSvcMockRepository()
	log := logger.NewNop()
	svc := app.NewBranchService(repo, log)
	return svc, repo
}

func makeBranchSvcTestBranch(repoID shared.ID, name string, isDefault bool) *branch.Branch {
	id := shared.NewID()
	now := time.Now().UTC()
	return branch.Reconstitute(
		id, repoID, name, branch.TypeFeature,
		isDefault, false,
		"", "", "", "", nil,
		true, true,
		nil, nil,
		branch.ScanStatusNotScanned, branch.QualityGateNotComputed,
		0, 0, 0, 0, 0,
		true, nil,
		now, now,
	)
}

// ============================================================================
// CreateBranch Tests
// ============================================================================

func TestBranchService_CreateBranch_Success(t *testing.T) {
	svc, repo := newTestBranchService()
	ctx := context.Background()
	repoID := shared.NewID()

	input := app.CreateBranchInput{
		RepositoryID: repoID.String(),
		Name:         "feature/login",
		BranchType:   "feature",
	}

	result, err := svc.CreateBranch(ctx, input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.Name() != "feature/login" {
		t.Errorf("expected name 'feature/login', got %q", result.Name())
	}
	if result.Type() != branch.TypeFeature {
		t.Errorf("expected type feature, got %q", result.Type())
	}
	if result.RepositoryID() != repoID {
		t.Errorf("expected repository ID %s, got %s", repoID, result.RepositoryID())
	}
	if _, ok := repo.branches[result.ID().String()]; !ok {
		t.Error("expected branch to be stored in repository")
	}
}

func TestBranchService_CreateBranch_WithDefaults(t *testing.T) {
	svc, _ := newTestBranchService()
	ctx := context.Background()
	repoID := shared.NewID()

	input := app.CreateBranchInput{
		RepositoryID:  repoID.String(),
		Name:          "main",
		BranchType:    "main",
		IsDefault:     true,
		IsProtected:   true,
		LastCommitSHA: "abc123def456",
	}

	result, err := svc.CreateBranch(ctx, input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !result.IsDefault() {
		t.Error("expected branch to be default")
	}
	if !result.IsProtected() {
		t.Error("expected branch to be protected")
	}
	if result.LastCommitSHA() != "abc123def456" {
		t.Errorf("expected last commit SHA 'abc123def456', got %q", result.LastCommitSHA())
	}
}

func TestBranchService_CreateBranch_InvalidRepositoryID(t *testing.T) {
	svc, _ := newTestBranchService()
	ctx := context.Background()

	input := app.CreateBranchInput{
		RepositoryID: "not-a-uuid",
		Name:         "main",
		BranchType:   "main",
	}

	_, err := svc.CreateBranch(ctx, input)
	if err == nil {
		t.Fatal("expected error for invalid repository ID")
	}
	if !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestBranchService_CreateBranch_AlreadyExists(t *testing.T) {
	svc, repo := newTestBranchService()
	ctx := context.Background()
	repoID := shared.NewID()

	existing := makeBranchSvcTestBranch(repoID, "main", true)
	repo.branches[existing.ID().String()] = existing

	input := app.CreateBranchInput{
		RepositoryID: repoID.String(),
		Name:         "main",
		BranchType:   "main",
	}

	_, err := svc.CreateBranch(ctx, input)
	if err == nil {
		t.Fatal("expected error for duplicate branch name")
	}
	if !errors.Is(err, branch.ErrAlreadyExists) {
		t.Errorf("expected ErrAlreadyExists, got %v", err)
	}
}

func TestBranchService_CreateBranch_ExistenceCheckError(t *testing.T) {
	svc, repo := newTestBranchService()
	ctx := context.Background()
	repoID := shared.NewID()

	dbErr := errors.New("database error")
	repo.existsByNameFn = func(_ context.Context, _ shared.ID, _ string) (bool, error) {
		return false, dbErr
	}

	input := app.CreateBranchInput{
		RepositoryID: repoID.String(),
		Name:         "main",
		BranchType:   "main",
	}

	_, err := svc.CreateBranch(ctx, input)
	if err == nil {
		t.Fatal("expected error from existence check")
	}
}

func TestBranchService_CreateBranch_RepositoryCreateError(t *testing.T) {
	svc, repo := newTestBranchService()
	ctx := context.Background()
	repoID := shared.NewID()

	repo.createErr = errors.New("create failed")

	input := app.CreateBranchInput{
		RepositoryID: repoID.String(),
		Name:         "develop",
		BranchType:   "develop",
	}

	_, err := svc.CreateBranch(ctx, input)
	if err == nil {
		t.Fatal("expected error from repository create")
	}
}

func TestBranchService_CreateBranch_InvalidTypeDefaultsToOther(t *testing.T) {
	svc, _ := newTestBranchService()
	ctx := context.Background()
	repoID := shared.NewID()

	input := app.CreateBranchInput{
		RepositoryID: repoID.String(),
		Name:         "my-branch",
		BranchType:   "unknown_type",
	}

	result, err := svc.CreateBranch(ctx, input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.Type() != branch.TypeOther {
		t.Errorf("expected type 'other' for unknown input, got %q", result.Type())
	}
}

// ============================================================================
// GetBranch Tests
// ============================================================================

func TestBranchService_GetBranch_Success(t *testing.T) {
	svc, repo := newTestBranchService()
	ctx := context.Background()
	repoID := shared.NewID()

	b := makeBranchSvcTestBranch(repoID, "main", true)
	repo.branches[b.ID().String()] = b

	result, err := svc.GetBranch(ctx, b.ID().String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.ID() != b.ID() {
		t.Errorf("expected branch ID %s, got %s", b.ID(), result.ID())
	}
}

func TestBranchService_GetBranch_InvalidID(t *testing.T) {
	svc, _ := newTestBranchService()
	ctx := context.Background()

	_, err := svc.GetBranch(ctx, "not-a-uuid")
	if err == nil {
		t.Fatal("expected error for invalid ID")
	}
	if !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestBranchService_GetBranch_NotFound(t *testing.T) {
	svc, _ := newTestBranchService()
	ctx := context.Background()

	id := shared.NewID()
	_, err := svc.GetBranch(ctx, id.String())
	if err == nil {
		t.Fatal("expected error for not found branch")
	}
	if !errors.Is(err, branch.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

// ============================================================================
// GetBranchByName Tests
// ============================================================================

func TestBranchService_GetBranchByName_Success(t *testing.T) {
	svc, repo := newTestBranchService()
	ctx := context.Background()
	repoID := shared.NewID()

	b := makeBranchSvcTestBranch(repoID, "develop", false)
	repo.branches[b.ID().String()] = b

	result, err := svc.GetBranchByName(ctx, repoID.String(), "develop")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.Name() != "develop" {
		t.Errorf("expected name 'develop', got %q", result.Name())
	}
}

func TestBranchService_GetBranchByName_InvalidRepositoryID(t *testing.T) {
	svc, _ := newTestBranchService()
	ctx := context.Background()

	_, err := svc.GetBranchByName(ctx, "bad-uuid", "main")
	if err == nil {
		t.Fatal("expected error for invalid repository ID")
	}
	if !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestBranchService_GetBranchByName_NotFound(t *testing.T) {
	svc, _ := newTestBranchService()
	ctx := context.Background()
	repoID := shared.NewID()

	_, err := svc.GetBranchByName(ctx, repoID.String(), "nonexistent")
	if err == nil {
		t.Fatal("expected error for not found branch")
	}
}

// ============================================================================
// UpdateBranch Tests
// ============================================================================

func TestBranchService_UpdateBranch_Success(t *testing.T) {
	svc, repo := newTestBranchService()
	ctx := context.Background()
	repoID := shared.NewID()

	b := makeBranchSvcTestBranch(repoID, "main", true)
	repo.branches[b.ID().String()] = b

	isProtected := true
	input := app.UpdateBranchInput{
		IsProtected: &isProtected,
	}

	result, err := svc.UpdateBranch(ctx, b.ID().String(), repoID.String(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !result.IsProtected() {
		t.Error("expected branch to be protected after update")
	}
}

func TestBranchService_UpdateBranch_WithCommitInfo(t *testing.T) {
	svc, repo := newTestBranchService()
	ctx := context.Background()
	repoID := shared.NewID()

	b := makeBranchSvcTestBranch(repoID, "develop", false)
	repo.branches[b.ID().String()] = b

	sha := "abc123"
	message := "fix: resolve login issue"
	author := "John Doe"
	avatar := "https://example.com/avatar.png"
	input := app.UpdateBranchInput{
		LastCommitSHA:          &sha,
		LastCommitMessage:      &message,
		LastCommitAuthor:       &author,
		LastCommitAuthorAvatar: &avatar,
	}

	result, err := svc.UpdateBranch(ctx, b.ID().String(), repoID.String(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.LastCommitSHA() != "abc123" {
		t.Errorf("expected SHA 'abc123', got %q", result.LastCommitSHA())
	}
	if result.LastCommitMessage() != "fix: resolve login issue" {
		t.Errorf("expected message, got %q", result.LastCommitMessage())
	}
	if result.LastCommitAuthor() != "John Doe" {
		t.Errorf("expected author 'John Doe', got %q", result.LastCommitAuthor())
	}
}

func TestBranchService_UpdateBranch_WithScanConfig(t *testing.T) {
	svc, repo := newTestBranchService()
	ctx := context.Background()
	repoID := shared.NewID()

	b := makeBranchSvcTestBranch(repoID, "main", true)
	repo.branches[b.ID().String()] = b

	scanOnPush := false
	scanOnPR := true
	input := app.UpdateBranchInput{
		ScanOnPush: &scanOnPush,
		ScanOnPR:   &scanOnPR,
	}

	result, err := svc.UpdateBranch(ctx, b.ID().String(), repoID.String(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.ScanOnPush() {
		t.Error("expected ScanOnPush to be false")
	}
	if !result.ScanOnPR() {
		t.Error("expected ScanOnPR to be true")
	}
}

func TestBranchService_UpdateBranch_WithRetention(t *testing.T) {
	svc, repo := newTestBranchService()
	ctx := context.Background()
	repoID := shared.NewID()

	b := makeBranchSvcTestBranch(repoID, "feature/test", false)
	repo.branches[b.ID().String()] = b

	keepWhenInactive := false
	retentionDays := 30
	input := app.UpdateBranchInput{
		KeepWhenInactive: &keepWhenInactive,
		RetentionDays:    &retentionDays,
	}

	result, err := svc.UpdateBranch(ctx, b.ID().String(), repoID.String(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.KeepWhenInactive() {
		t.Error("expected KeepWhenInactive to be false")
	}
	if result.RetentionDays() == nil || *result.RetentionDays() != 30 {
		t.Error("expected retention days to be 30")
	}
}

func TestBranchService_UpdateBranch_InvalidID(t *testing.T) {
	svc, _ := newTestBranchService()
	ctx := context.Background()

	_, err := svc.UpdateBranch(ctx, "bad-id", "", app.UpdateBranchInput{})
	if err == nil {
		t.Fatal("expected error for invalid ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestBranchService_UpdateBranch_NotFound(t *testing.T) {
	svc, _ := newTestBranchService()
	ctx := context.Background()

	id := shared.NewID()
	_, err := svc.UpdateBranch(ctx, id.String(), "", app.UpdateBranchInput{})
	if err == nil {
		t.Fatal("expected error for not found branch")
	}
}

func TestBranchService_UpdateBranch_IDORPrevention(t *testing.T) {
	svc, repo := newTestBranchService()
	ctx := context.Background()
	repoID := shared.NewID()
	wrongRepoID := shared.NewID()

	b := makeBranchSvcTestBranch(repoID, "main", true)
	repo.branches[b.ID().String()] = b

	_, err := svc.UpdateBranch(ctx, b.ID().String(), wrongRepoID.String(), app.UpdateBranchInput{})
	if err == nil {
		t.Fatal("expected error for IDOR prevention")
	}
	if !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("expected ErrNotFound for IDOR, got %v", err)
	}
}

func TestBranchService_UpdateBranch_EmptyRepositoryIDSkipsIDOR(t *testing.T) {
	svc, repo := newTestBranchService()
	ctx := context.Background()
	repoID := shared.NewID()

	b := makeBranchSvcTestBranch(repoID, "main", true)
	repo.branches[b.ID().String()] = b

	result, err := svc.UpdateBranch(ctx, b.ID().String(), "", app.UpdateBranchInput{})
	if err != nil {
		t.Fatalf("expected no error when repositoryID is empty, got %v", err)
	}
	if result.ID() != b.ID() {
		t.Error("expected to get the branch back")
	}
}

func TestBranchService_UpdateBranch_RepositoryUpdateError(t *testing.T) {
	svc, repo := newTestBranchService()
	ctx := context.Background()
	repoID := shared.NewID()

	b := makeBranchSvcTestBranch(repoID, "main", true)
	repo.branches[b.ID().String()] = b
	repo.updateErr = errors.New("update failed")

	isProtected := true
	input := app.UpdateBranchInput{IsProtected: &isProtected}

	_, err := svc.UpdateBranch(ctx, b.ID().String(), repoID.String(), input)
	if err == nil {
		t.Fatal("expected error from repository update")
	}
}

// ============================================================================
// DeleteBranch Tests
// ============================================================================

func TestBranchService_DeleteBranch_Success(t *testing.T) {
	svc, repo := newTestBranchService()
	ctx := context.Background()
	repoID := shared.NewID()

	b := makeBranchSvcTestBranch(repoID, "feature/old", false)
	repo.branches[b.ID().String()] = b

	err := svc.DeleteBranch(ctx, b.ID().String(), repoID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if _, ok := repo.branches[b.ID().String()]; ok {
		t.Error("expected branch to be deleted from repository")
	}
}

func TestBranchService_DeleteBranch_InvalidID(t *testing.T) {
	svc, _ := newTestBranchService()
	ctx := context.Background()

	err := svc.DeleteBranch(ctx, "bad-id", "")
	if err == nil {
		t.Fatal("expected error for invalid ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestBranchService_DeleteBranch_NotFound(t *testing.T) {
	svc, _ := newTestBranchService()
	ctx := context.Background()
	repoID := shared.NewID()
	branchID := shared.NewID()

	err := svc.DeleteBranch(ctx, branchID.String(), repoID.String())
	if err == nil {
		t.Fatal("expected error for not found branch")
	}
}

func TestBranchService_DeleteBranch_IDORPrevention(t *testing.T) {
	svc, repo := newTestBranchService()
	ctx := context.Background()
	repoID := shared.NewID()
	wrongRepoID := shared.NewID()

	b := makeBranchSvcTestBranch(repoID, "feature/x", false)
	repo.branches[b.ID().String()] = b

	err := svc.DeleteBranch(ctx, b.ID().String(), wrongRepoID.String())
	if err == nil {
		t.Fatal("expected error for IDOR prevention")
	}
	if !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("expected ErrNotFound for IDOR, got %v", err)
	}
}

func TestBranchService_DeleteBranch_CannotDeleteDefault(t *testing.T) {
	svc, repo := newTestBranchService()
	ctx := context.Background()
	repoID := shared.NewID()

	b := makeBranchSvcTestBranch(repoID, "main", true) // isDefault = true
	repo.branches[b.ID().String()] = b

	err := svc.DeleteBranch(ctx, b.ID().String(), repoID.String())
	if err == nil {
		t.Fatal("expected error when deleting default branch")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestBranchService_DeleteBranch_EmptyRepositoryIDSkipsChecks(t *testing.T) {
	svc, repo := newTestBranchService()
	ctx := context.Background()
	repoID := shared.NewID()

	b := makeBranchSvcTestBranch(repoID, "feature/y", false)
	repo.branches[b.ID().String()] = b

	err := svc.DeleteBranch(ctx, b.ID().String(), "")
	if err != nil {
		t.Fatalf("expected no error when repositoryID is empty, got %v", err)
	}
}

func TestBranchService_DeleteBranch_RepositoryDeleteError(t *testing.T) {
	svc, repo := newTestBranchService()
	ctx := context.Background()
	repoID := shared.NewID()

	b := makeBranchSvcTestBranch(repoID, "feature/z", false)
	repo.branches[b.ID().String()] = b
	repo.deleteErr = errors.New("delete failed")

	err := svc.DeleteBranch(ctx, b.ID().String(), repoID.String())
	if err == nil {
		t.Fatal("expected error from repository delete")
	}
}

// ============================================================================
// ListBranches Tests
// ============================================================================

func TestBranchService_ListBranches_Success(t *testing.T) {
	svc, repo := newTestBranchService()
	ctx := context.Background()
	repoID := shared.NewID()

	b1 := makeBranchSvcTestBranch(repoID, "main", true)
	b2 := makeBranchSvcTestBranch(repoID, "develop", false)
	repo.branches[b1.ID().String()] = b1
	repo.branches[b2.ID().String()] = b2

	input := app.ListBranchesInput{
		RepositoryID: repoID.String(),
		Page:         1,
		PerPage:      10,
	}

	result, err := svc.ListBranches(ctx, input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.Total != 2 {
		t.Errorf("expected total 2, got %d", result.Total)
	}
}

func TestBranchService_ListBranches_InvalidRepositoryID(t *testing.T) {
	svc, _ := newTestBranchService()
	ctx := context.Background()

	input := app.ListBranchesInput{
		RepositoryID: "bad-uuid",
		Page:         1,
		PerPage:      10,
	}

	_, err := svc.ListBranches(ctx, input)
	if err == nil {
		t.Fatal("expected error for invalid repository ID")
	}
	if !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestBranchService_ListBranches_WithFilters(t *testing.T) {
	svc, repo := newTestBranchService()
	ctx := context.Background()
	repoID := shared.NewID()

	b1 := makeBranchSvcTestBranch(repoID, "main", true)
	repo.branches[b1.ID().String()] = b1

	isDefault := true
	input := app.ListBranchesInput{
		RepositoryID: repoID.String(),
		Name:         "main",
		BranchTypes:  []string{"main"},
		IsDefault:    &isDefault,
		ScanStatus:   "passed",
		Sort:         "-created_at",
		Page:         1,
		PerPage:      10,
	}

	_, err := svc.ListBranches(ctx, input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestBranchService_ListBranches_SortAscending(t *testing.T) {
	svc, repo := newTestBranchService()
	ctx := context.Background()
	repoID := shared.NewID()

	b := makeBranchSvcTestBranch(repoID, "main", true)
	repo.branches[b.ID().String()] = b

	input := app.ListBranchesInput{
		RepositoryID: repoID.String(),
		Sort:         "name",
		Page:         1,
		PerPage:      10,
	}

	_, err := svc.ListBranches(ctx, input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestBranchService_ListBranches_RepoError(t *testing.T) {
	svc, repo := newTestBranchService()
	ctx := context.Background()
	repoID := shared.NewID()

	repo.listErr = errors.New("database error")

	input := app.ListBranchesInput{
		RepositoryID: repoID.String(),
		Page:         1,
		PerPage:      10,
	}

	_, err := svc.ListBranches(ctx, input)
	if err == nil {
		t.Fatal("expected error from repository")
	}
}

// ============================================================================
// ListRepositoryBranches Tests
// ============================================================================

func TestBranchService_ListRepositoryBranches_Success(t *testing.T) {
	svc, repo := newTestBranchService()
	ctx := context.Background()
	repoID := shared.NewID()

	b1 := makeBranchSvcTestBranch(repoID, "main", true)
	b2 := makeBranchSvcTestBranch(repoID, "develop", false)
	otherRepoID := shared.NewID()
	b3 := makeBranchSvcTestBranch(otherRepoID, "main", true)
	repo.branches[b1.ID().String()] = b1
	repo.branches[b2.ID().String()] = b2
	repo.branches[b3.ID().String()] = b3

	result, err := svc.ListRepositoryBranches(ctx, repoID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(result) != 2 {
		t.Errorf("expected 2 branches, got %d", len(result))
	}
}

func TestBranchService_ListRepositoryBranches_InvalidID(t *testing.T) {
	svc, _ := newTestBranchService()
	ctx := context.Background()

	_, err := svc.ListRepositoryBranches(ctx, "bad-uuid")
	if err == nil {
		t.Fatal("expected error for invalid ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestBranchService_ListRepositoryBranches_RepoError(t *testing.T) {
	svc, repo := newTestBranchService()
	ctx := context.Background()
	repoID := shared.NewID()

	repo.listByRepoErr = errors.New("database error")

	_, err := svc.ListRepositoryBranches(ctx, repoID.String())
	if err == nil {
		t.Fatal("expected error from repository")
	}
}

// ============================================================================
// GetDefaultBranch Tests
// ============================================================================

func TestBranchService_GetDefaultBranch_Success(t *testing.T) {
	svc, repo := newTestBranchService()
	ctx := context.Background()
	repoID := shared.NewID()

	b := makeBranchSvcTestBranch(repoID, "main", true)
	repo.defaultBranch = b

	result, err := svc.GetDefaultBranch(ctx, repoID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !result.IsDefault() {
		t.Error("expected default branch")
	}
}

func TestBranchService_GetDefaultBranch_InvalidID(t *testing.T) {
	svc, _ := newTestBranchService()
	ctx := context.Background()

	_, err := svc.GetDefaultBranch(ctx, "bad-uuid")
	if err == nil {
		t.Fatal("expected error for invalid ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestBranchService_GetDefaultBranch_NotFound(t *testing.T) {
	svc, _ := newTestBranchService()
	ctx := context.Background()
	repoID := shared.NewID()

	_, err := svc.GetDefaultBranch(ctx, repoID.String())
	if err == nil {
		t.Fatal("expected error for no default branch")
	}
}

// ============================================================================
// SetDefaultBranch Tests
// ============================================================================

func TestBranchService_SetDefaultBranch_Success(t *testing.T) {
	svc, repo := newTestBranchService()
	ctx := context.Background()
	repoID := shared.NewID()

	b := makeBranchSvcTestBranch(repoID, "develop", false)
	repo.branches[b.ID().String()] = b

	result, err := svc.SetDefaultBranch(ctx, b.ID().String(), repoID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !result.IsDefault() {
		t.Error("expected branch to be set as default")
	}
}

func TestBranchService_SetDefaultBranch_InvalidBranchID(t *testing.T) {
	svc, _ := newTestBranchService()
	ctx := context.Background()
	repoID := shared.NewID()

	_, err := svc.SetDefaultBranch(ctx, "bad-id", repoID.String())
	if err == nil {
		t.Fatal("expected error for invalid branch ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestBranchService_SetDefaultBranch_InvalidRepositoryID(t *testing.T) {
	svc, _ := newTestBranchService()
	ctx := context.Background()
	branchID := shared.NewID()

	_, err := svc.SetDefaultBranch(ctx, branchID.String(), "bad-uuid")
	if err == nil {
		t.Fatal("expected error for invalid repository ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestBranchService_SetDefaultBranch_BranchNotFound(t *testing.T) {
	svc, _ := newTestBranchService()
	ctx := context.Background()
	branchID := shared.NewID()
	repoID := shared.NewID()

	_, err := svc.SetDefaultBranch(ctx, branchID.String(), repoID.String())
	if err == nil {
		t.Fatal("expected error for not found branch")
	}
}

func TestBranchService_SetDefaultBranch_IDORPrevention(t *testing.T) {
	svc, repo := newTestBranchService()
	ctx := context.Background()
	repoID := shared.NewID()
	wrongRepoID := shared.NewID()

	b := makeBranchSvcTestBranch(repoID, "develop", false)
	repo.branches[b.ID().String()] = b

	_, err := svc.SetDefaultBranch(ctx, b.ID().String(), wrongRepoID.String())
	if err == nil {
		t.Fatal("expected error for IDOR prevention")
	}
	if !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("expected ErrNotFound for IDOR, got %v", err)
	}
}

func TestBranchService_SetDefaultBranch_SetDefaultError(t *testing.T) {
	svc, repo := newTestBranchService()
	ctx := context.Background()
	repoID := shared.NewID()

	b := makeBranchSvcTestBranch(repoID, "develop", false)
	repo.branches[b.ID().String()] = b
	repo.setDefaultErr = errors.New("set default failed")

	_, err := svc.SetDefaultBranch(ctx, b.ID().String(), repoID.String())
	if err == nil {
		t.Fatal("expected error from repository")
	}
}

// ============================================================================
// UpdateBranchScanStatus Tests
// ============================================================================

func TestBranchService_UpdateBranchScanStatus_Success(t *testing.T) {
	svc, repo := newTestBranchService()
	ctx := context.Background()
	repoID := shared.NewID()
	scanID := shared.NewID()

	b := makeBranchSvcTestBranch(repoID, "main", true)
	repo.branches[b.ID().String()] = b

	total, critical, high, medium, low := 10, 2, 3, 3, 2
	input := app.UpdateBranchScanStatusInput{
		ScanID:           scanID.String(),
		ScanStatus:       "passed",
		QualityGate:      "passed",
		TotalFindings:    &total,
		CriticalFindings: &critical,
		HighFindings:     &high,
		MediumFindings:   &medium,
		LowFindings:      &low,
	}

	result, err := svc.UpdateBranchScanStatus(ctx, b.ID().String(), repoID.String(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.ScanStatus() != branch.ScanStatusPassed {
		t.Errorf("expected scan status passed, got %q", result.ScanStatus())
	}
	if result.QualityGateStatus() != branch.QualityGatePassed {
		t.Errorf("expected quality gate passed, got %q", result.QualityGateStatus())
	}
	if result.FindingsTotal() != 10 {
		t.Errorf("expected findings total 10, got %d", result.FindingsTotal())
	}
	if result.FindingsCritical() != 2 {
		t.Errorf("expected critical 2, got %d", result.FindingsCritical())
	}
}

func TestBranchService_UpdateBranchScanStatus_WithoutFindings(t *testing.T) {
	svc, repo := newTestBranchService()
	ctx := context.Background()
	repoID := shared.NewID()
	scanID := shared.NewID()

	b := makeBranchSvcTestBranch(repoID, "develop", false)
	repo.branches[b.ID().String()] = b

	input := app.UpdateBranchScanStatusInput{
		ScanID:     scanID.String(),
		ScanStatus: "scanning",
	}

	result, err := svc.UpdateBranchScanStatus(ctx, b.ID().String(), repoID.String(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.ScanStatus() != branch.ScanStatusScanning {
		t.Errorf("expected scan status scanning, got %q", result.ScanStatus())
	}
	if result.QualityGateStatus() != branch.QualityGateNotComputed {
		t.Errorf("expected quality gate not_computed when empty, got %q", result.QualityGateStatus())
	}
	// Findings should remain at 0
	if result.FindingsTotal() != 0 {
		t.Errorf("expected findings total 0, got %d", result.FindingsTotal())
	}
}

func TestBranchService_UpdateBranchScanStatus_InvalidBranchID(t *testing.T) {
	svc, _ := newTestBranchService()
	ctx := context.Background()

	input := app.UpdateBranchScanStatusInput{
		ScanID:     shared.NewID().String(),
		ScanStatus: "passed",
	}

	_, err := svc.UpdateBranchScanStatus(ctx, "bad-id", "", input)
	if err == nil {
		t.Fatal("expected error for invalid branch ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestBranchService_UpdateBranchScanStatus_BranchNotFound(t *testing.T) {
	svc, _ := newTestBranchService()
	ctx := context.Background()

	input := app.UpdateBranchScanStatusInput{
		ScanID:     shared.NewID().String(),
		ScanStatus: "passed",
	}

	id := shared.NewID()
	_, err := svc.UpdateBranchScanStatus(ctx, id.String(), "", input)
	if err == nil {
		t.Fatal("expected error for not found branch")
	}
}

func TestBranchService_UpdateBranchScanStatus_IDORPrevention(t *testing.T) {
	svc, repo := newTestBranchService()
	ctx := context.Background()
	repoID := shared.NewID()
	wrongRepoID := shared.NewID()

	b := makeBranchSvcTestBranch(repoID, "main", true)
	repo.branches[b.ID().String()] = b

	input := app.UpdateBranchScanStatusInput{
		ScanID:     shared.NewID().String(),
		ScanStatus: "passed",
	}

	_, err := svc.UpdateBranchScanStatus(ctx, b.ID().String(), wrongRepoID.String(), input)
	if err == nil {
		t.Fatal("expected error for IDOR prevention")
	}
	if !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestBranchService_UpdateBranchScanStatus_InvalidScanID(t *testing.T) {
	svc, repo := newTestBranchService()
	ctx := context.Background()
	repoID := shared.NewID()

	b := makeBranchSvcTestBranch(repoID, "main", true)
	repo.branches[b.ID().String()] = b

	input := app.UpdateBranchScanStatusInput{
		ScanID:     "bad-scan-id",
		ScanStatus: "passed",
	}

	_, err := svc.UpdateBranchScanStatus(ctx, b.ID().String(), repoID.String(), input)
	if err == nil {
		t.Fatal("expected error for invalid scan ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestBranchService_UpdateBranchScanStatus_UpdateError(t *testing.T) {
	svc, repo := newTestBranchService()
	ctx := context.Background()
	repoID := shared.NewID()

	b := makeBranchSvcTestBranch(repoID, "main", true)
	repo.branches[b.ID().String()] = b
	repo.updateErr = errors.New("update failed")

	input := app.UpdateBranchScanStatusInput{
		ScanID:     shared.NewID().String(),
		ScanStatus: "passed",
	}

	_, err := svc.UpdateBranchScanStatus(ctx, b.ID().String(), repoID.String(), input)
	if err == nil {
		t.Fatal("expected error from repository update")
	}
}

func TestBranchService_UpdateBranchScanStatus_PartialFindingsNotApplied(t *testing.T) {
	svc, repo := newTestBranchService()
	ctx := context.Background()
	repoID := shared.NewID()

	b := makeBranchSvcTestBranch(repoID, "main", true)
	repo.branches[b.ID().String()] = b

	// Only provide some findings - should not update stats since all 5 are required
	total := 10
	input := app.UpdateBranchScanStatusInput{
		ScanID:        shared.NewID().String(),
		ScanStatus:    "passed",
		TotalFindings: &total,
	}

	result, err := svc.UpdateBranchScanStatus(ctx, b.ID().String(), repoID.String(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.FindingsTotal() != 0 {
		t.Errorf("expected findings not updated with partial input, got %d", result.FindingsTotal())
	}
}

// ============================================================================
// CountRepositoryBranches Tests
// ============================================================================

func TestBranchService_CountRepositoryBranches_Success(t *testing.T) {
	svc, repo := newTestBranchService()
	ctx := context.Background()
	repoID := shared.NewID()

	b1 := makeBranchSvcTestBranch(repoID, "main", true)
	b2 := makeBranchSvcTestBranch(repoID, "develop", false)
	repo.branches[b1.ID().String()] = b1
	repo.branches[b2.ID().String()] = b2

	count, err := svc.CountRepositoryBranches(ctx, repoID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if count != 2 {
		t.Errorf("expected count 2, got %d", count)
	}
}

func TestBranchService_CountRepositoryBranches_InvalidID(t *testing.T) {
	svc, _ := newTestBranchService()
	ctx := context.Background()

	_, err := svc.CountRepositoryBranches(ctx, "bad-uuid")
	if err == nil {
		t.Fatal("expected error for invalid repository ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestBranchService_CountRepositoryBranches_RepoError(t *testing.T) {
	svc, repo := newTestBranchService()
	ctx := context.Background()
	repoID := shared.NewID()

	repo.countErr = errors.New("count failed")

	_, err := svc.CountRepositoryBranches(ctx, repoID.String())
	if err == nil {
		t.Fatal("expected error from repository count")
	}
}

func TestBranchService_CountRepositoryBranches_Empty(t *testing.T) {
	svc, _ := newTestBranchService()
	ctx := context.Background()
	repoID := shared.NewID()

	count, err := svc.CountRepositoryBranches(ctx, repoID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if count != 0 {
		t.Errorf("expected count 0, got %d", count)
	}
}
