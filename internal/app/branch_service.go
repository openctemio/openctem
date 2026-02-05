package app

import (
	"context"
	"fmt"
	"time"

	"github.com/openctemio/api/pkg/domain/branch"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
)

// BranchService handles branch-related business operations.
type BranchService struct {
	repo   branch.Repository
	logger *logger.Logger
}

// NewBranchService creates a new BranchService.
func NewBranchService(repo branch.Repository, log *logger.Logger) *BranchService {
	return &BranchService{
		repo:   repo,
		logger: log.With("service", "branch"),
	}
}

// CreateBranchInput represents the input for creating a branch.
type CreateBranchInput struct {
	RepositoryID  string `validate:"required,uuid"`
	Name          string `validate:"required,min=1,max=255"`
	BranchType    string `validate:"required,branch_type"`
	IsDefault     bool
	IsProtected   bool
	LastCommitSHA string `validate:"max=40"`
}

// CreateBranch creates a new branch.
func (s *BranchService) CreateBranch(ctx context.Context, input CreateBranchInput) (*branch.Branch, error) {
	s.logger.Info("creating branch", "name", input.Name, "repository_id", input.RepositoryID)

	repositoryID, err := shared.IDFromString(input.RepositoryID)
	if err != nil {
		return nil, shared.ErrNotFound
	}

	branchType := branch.ParseType(input.BranchType)

	// Check if branch already exists
	exists, err := s.repo.ExistsByName(ctx, repositoryID, input.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to check branch existence: %w", err)
	}
	if exists {
		return nil, branch.AlreadyExistsError(input.Name)
	}

	b, err := branch.NewBranch(repositoryID, input.Name, branchType)
	if err != nil {
		return nil, err
	}

	if input.IsDefault {
		b.SetDefault(true)
	}

	if input.IsProtected {
		b.SetProtected(true)
	}

	if input.LastCommitSHA != "" {
		b.UpdateLastCommit(input.LastCommitSHA, "", "", "", time.Now().UTC())
	}

	if err := s.repo.Create(ctx, b); err != nil {
		return nil, fmt.Errorf("failed to create branch: %w", err)
	}

	s.logger.Info("branch created", "id", b.ID().String(), "name", b.Name())
	return b, nil
}

// GetBranch retrieves a branch by ID.
func (s *BranchService) GetBranch(ctx context.Context, branchID string) (*branch.Branch, error) {
	parsedID, err := shared.IDFromString(branchID)
	if err != nil {
		return nil, shared.ErrNotFound
	}

	return s.repo.GetByID(ctx, parsedID)
}

// GetBranchByName retrieves a branch by repository ID and name.
func (s *BranchService) GetBranchByName(ctx context.Context, repositoryID, name string) (*branch.Branch, error) {
	parsedRepositoryID, err := shared.IDFromString(repositoryID)
	if err != nil {
		return nil, shared.ErrNotFound
	}

	return s.repo.GetByName(ctx, parsedRepositoryID, name)
}

// UpdateBranchInput represents the input for updating a branch.
type UpdateBranchInput struct {
	IsProtected            *bool
	LastCommitSHA          *string `validate:"omitempty,max=40"`
	LastCommitMessage      *string `validate:"omitempty,max=1000"`
	LastCommitAuthor       *string `validate:"omitempty,max=100"`
	LastCommitAuthorAvatar *string `validate:"omitempty,max=500"`
	ScanOnPush             *bool
	ScanOnPR               *bool
	KeepWhenInactive       *bool
	RetentionDays          *int `validate:"omitempty,min=0,max=365"`
}

// UpdateBranch updates an existing branch.
func (s *BranchService) UpdateBranch(ctx context.Context, branchID, repositoryID string, input UpdateBranchInput) (*branch.Branch, error) {
	parsedID, err := shared.IDFromString(branchID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid id format", shared.ErrValidation)
	}

	b, err := s.repo.GetByID(ctx, parsedID)
	if err != nil {
		return nil, err
	}

	// IDOR prevention: verify branch belongs to the repository
	if repositoryID != "" && b.RepositoryID().String() != repositoryID {
		return nil, shared.ErrNotFound
	}

	if input.IsProtected != nil {
		b.SetProtected(*input.IsProtected)
	}

	if input.LastCommitSHA != nil {
		message := ""
		author := ""
		avatar := ""
		if input.LastCommitMessage != nil {
			message = *input.LastCommitMessage
		}
		if input.LastCommitAuthor != nil {
			author = *input.LastCommitAuthor
		}
		if input.LastCommitAuthorAvatar != nil {
			avatar = *input.LastCommitAuthorAvatar
		}
		b.UpdateLastCommit(*input.LastCommitSHA, message, author, avatar, time.Now().UTC())
	}

	if input.ScanOnPush != nil || input.ScanOnPR != nil {
		scanOnPush := b.ScanOnPush()
		scanOnPR := b.ScanOnPR()
		if input.ScanOnPush != nil {
			scanOnPush = *input.ScanOnPush
		}
		if input.ScanOnPR != nil {
			scanOnPR = *input.ScanOnPR
		}
		b.SetScanConfig(scanOnPush, scanOnPR)
	}

	if input.KeepWhenInactive != nil || input.RetentionDays != nil {
		keepWhenInactive := b.KeepWhenInactive()
		retentionDays := b.RetentionDays()
		if input.KeepWhenInactive != nil {
			keepWhenInactive = *input.KeepWhenInactive
		}
		if input.RetentionDays != nil {
			retentionDays = input.RetentionDays
		}
		b.SetRetention(keepWhenInactive, retentionDays)
	}

	if err := s.repo.Update(ctx, b); err != nil {
		return nil, fmt.Errorf("failed to update branch: %w", err)
	}

	s.logger.Info("branch updated", "id", b.ID().String())
	return b, nil
}

// DeleteBranch deletes a branch by ID.
func (s *BranchService) DeleteBranch(ctx context.Context, branchID, repositoryID string) error {
	parsedID, err := shared.IDFromString(branchID)
	if err != nil {
		return fmt.Errorf("%w: invalid id format", shared.ErrValidation)
	}

	// IDOR prevention: verify branch belongs to the repository before deletion
	if repositoryID != "" {
		b, err := s.repo.GetByID(ctx, parsedID)
		if err != nil {
			return err
		}
		if b.RepositoryID().String() != repositoryID {
			return shared.ErrNotFound
		}
		// Prevent deletion of default branch
		if b.IsDefault() {
			return fmt.Errorf("%w: cannot delete default branch", shared.ErrValidation)
		}
	}

	if err := s.repo.Delete(ctx, parsedID); err != nil {
		return err
	}

	s.logger.Info("branch deleted", "id", branchID)
	return nil
}

// ListBranchesInput represents the input for listing branches.
type ListBranchesInput struct {
	RepositoryID string   `validate:"required,uuid"`
	Name         string   `validate:"max=255"`
	BranchTypes  []string `validate:"max=10,dive,branch_type"`
	IsDefault    *bool
	ScanStatus   string `validate:"omitempty,scan_status"`
	Sort         string `validate:"max=100"`
	Page         int    `validate:"min=0"`
	PerPage      int    `validate:"min=0,max=100"`
}

// ListBranches retrieves branches with filtering and pagination.
func (s *BranchService) ListBranches(ctx context.Context, input ListBranchesInput) (pagination.Result[*branch.Branch], error) {
	repositoryID, err := shared.IDFromString(input.RepositoryID)
	if err != nil {
		return pagination.Result[*branch.Branch]{}, shared.ErrNotFound
	}

	filter := branch.Filter{
		RepositoryID: &repositoryID,
	}

	if input.Name != "" {
		filter.Name = input.Name
	}

	if len(input.BranchTypes) > 0 {
		types := make([]branch.Type, 0, len(input.BranchTypes))
		for _, t := range input.BranchTypes {
			types = append(types, branch.ParseType(t))
		}
		filter.Types = types
	}

	if input.IsDefault != nil {
		filter.IsDefault = input.IsDefault
	}

	if input.ScanStatus != "" {
		status := branch.ParseScanStatus(input.ScanStatus)
		filter.ScanStatus = &status
	}

	opts := branch.ListOptions{}
	const SortOrderDesc = "desc"

	if input.Sort != "" {
		// Parse sort string like "-created_at" or "name"
		if input.Sort[0] == '-' {
			opts.SortBy = input.Sort[1:]
			opts.SortOrder = SortOrderDesc
		} else {
			opts.SortBy = input.Sort
			opts.SortOrder = "asc"
		}
	}

	page := pagination.New(input.Page, input.PerPage)
	return s.repo.List(ctx, filter, opts, page)
}

// ListRepositoryBranches retrieves all branches for a repository.
func (s *BranchService) ListRepositoryBranches(ctx context.Context, repositoryID string) ([]*branch.Branch, error) {
	parsedRepositoryID, err := shared.IDFromString(repositoryID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid repository id format", shared.ErrValidation)
	}

	return s.repo.ListByRepository(ctx, parsedRepositoryID)
}

// GetDefaultBranch retrieves the default branch for a repository.
func (s *BranchService) GetDefaultBranch(ctx context.Context, repositoryID string) (*branch.Branch, error) {
	parsedRepositoryID, err := shared.IDFromString(repositoryID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid repository id format", shared.ErrValidation)
	}

	return s.repo.GetDefaultBranch(ctx, parsedRepositoryID)
}

// SetDefaultBranch sets a branch as the default for a repository.
func (s *BranchService) SetDefaultBranch(ctx context.Context, branchID, repositoryID string) (*branch.Branch, error) {
	parsedID, err := shared.IDFromString(branchID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid id format", shared.ErrValidation)
	}

	parsedRepositoryID, err := shared.IDFromString(repositoryID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid repository id format", shared.ErrValidation)
	}

	// Verify branch belongs to the repository
	b, err := s.repo.GetByID(ctx, parsedID)
	if err != nil {
		return nil, err
	}
	if b.RepositoryID().String() != repositoryID {
		return nil, shared.ErrNotFound
	}

	if err := s.repo.SetDefaultBranch(ctx, parsedRepositoryID, parsedID); err != nil {
		return nil, fmt.Errorf("failed to set default branch: %w", err)
	}

	// Reload to get updated state
	b, err = s.repo.GetByID(ctx, parsedID)
	if err != nil {
		return nil, err
	}

	s.logger.Info("default branch set", "branch_id", branchID, "repository_id", repositoryID)
	return b, nil
}

// UpdateBranchScanStatusInput represents the input for updating scan status.
type UpdateBranchScanStatusInput struct {
	ScanID           string `validate:"required,uuid"`
	ScanStatus       string `validate:"required,scan_status"`
	QualityGate      string `validate:"omitempty,quality_gate_status"`
	TotalFindings    *int   `validate:"omitempty,min=0"`
	CriticalFindings *int   `validate:"omitempty,min=0"`
	HighFindings     *int   `validate:"omitempty,min=0"`
	MediumFindings   *int   `validate:"omitempty,min=0"`
	LowFindings      *int   `validate:"omitempty,min=0"`
}

// UpdateBranchScanStatus updates scan-related fields for a branch.
func (s *BranchService) UpdateBranchScanStatus(ctx context.Context, branchID, repositoryID string, input UpdateBranchScanStatusInput) (*branch.Branch, error) {
	parsedID, err := shared.IDFromString(branchID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid id format", shared.ErrValidation)
	}

	b, err := s.repo.GetByID(ctx, parsedID)
	if err != nil {
		return nil, err
	}

	// IDOR prevention
	if repositoryID != "" && b.RepositoryID().String() != repositoryID {
		return nil, shared.ErrNotFound
	}

	scanID, err := shared.IDFromString(input.ScanID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid scan id format", shared.ErrValidation)
	}

	scanStatus := branch.ParseScanStatus(input.ScanStatus)
	qgStatus := branch.QualityGateNotComputed
	if input.QualityGate != "" {
		qgStatus = branch.ParseQualityGateStatus(input.QualityGate)
	}

	b.MarkScanned(scanID, scanStatus, qgStatus)

	if input.TotalFindings != nil && input.CriticalFindings != nil &&
		input.HighFindings != nil && input.MediumFindings != nil && input.LowFindings != nil {
		b.UpdateFindingStats(*input.TotalFindings, *input.CriticalFindings,
			*input.HighFindings, *input.MediumFindings, *input.LowFindings)
	}

	if err := s.repo.Update(ctx, b); err != nil {
		return nil, fmt.Errorf("failed to update branch scan status: %w", err)
	}

	s.logger.Info("branch scan status updated", "id", branchID, "status", scanStatus.String())
	return b, nil
}

// CountRepositoryBranches counts branches for a repository.
func (s *BranchService) CountRepositoryBranches(ctx context.Context, repositoryID string) (int64, error) {
	parsedRepositoryID, err := shared.IDFromString(repositoryID)
	if err != nil {
		return 0, fmt.Errorf("%w: invalid repository id format", shared.ErrValidation)
	}

	filter := branch.Filter{
		RepositoryID: &parsedRepositoryID,
	}
	return s.repo.Count(ctx, filter)
}
