package app

import (
	"context"
	"fmt"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
	"github.com/openctemio/api/pkg/logger"
)

// FindingCommentService handles finding comment operations.
type FindingCommentService struct {
	commentRepo vulnerability.FindingCommentRepository
	findingRepo vulnerability.FindingRepository
	logger      *logger.Logger
}

// NewFindingCommentService creates a new FindingCommentService.
func NewFindingCommentService(
	commentRepo vulnerability.FindingCommentRepository,
	findingRepo vulnerability.FindingRepository,
	log *logger.Logger,
) *FindingCommentService {
	return &FindingCommentService{
		commentRepo: commentRepo,
		findingRepo: findingRepo,
		logger:      log.With("service", "finding_comment"),
	}
}

// AddCommentInput represents the input for adding a comment.
type AddCommentInput struct {
	TenantID  string `validate:"required,uuid"`
	FindingID string `validate:"required,uuid"`
	AuthorID  string `validate:"required,uuid"`
	Content   string `validate:"required,min=1,max=10000"`
}

// AddComment adds a new comment to a finding.
func (s *FindingCommentService) AddComment(ctx context.Context, input AddCommentInput) (*vulnerability.FindingComment, error) {
	s.logger.Info("adding comment to finding", "finding_id", input.FindingID)

	tenantID, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id format", shared.ErrValidation)
	}

	findingID, err := shared.IDFromString(input.FindingID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid finding id format", shared.ErrValidation)
	}

	authorID, err := shared.IDFromString(input.AuthorID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid author id format", shared.ErrValidation)
	}

	// Verify finding exists and belongs to tenant
	_, err = s.findingRepo.GetByID(ctx, tenantID, findingID)
	if err != nil {
		return nil, err
	}

	comment, err := vulnerability.NewFindingComment(findingID, authorID, input.Content)
	if err != nil {
		return nil, err
	}

	if err := s.commentRepo.Create(ctx, comment); err != nil {
		return nil, fmt.Errorf("failed to create comment: %w", err)
	}

	s.logger.Info("comment added", "comment_id", comment.ID().String(), "finding_id", input.FindingID)
	return comment, nil
}

// AddStatusChangeCommentInput represents the input for adding a status change comment.
type AddStatusChangeCommentInput struct {
	FindingID string `validate:"required,uuid"`
	AuthorID  string `validate:"required,uuid"`
	Content   string `validate:"max=10000"`
	OldStatus string `validate:"required,finding_status"`
	NewStatus string `validate:"required,finding_status"`
}

// AddStatusChangeComment adds a comment recording a status change.
func (s *FindingCommentService) AddStatusChangeComment(ctx context.Context, input AddStatusChangeCommentInput) (*vulnerability.FindingComment, error) {
	s.logger.Info("adding status change comment", "finding_id", input.FindingID, "old_status", input.OldStatus, "new_status", input.NewStatus)

	findingID, err := shared.IDFromString(input.FindingID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid finding id format", shared.ErrValidation)
	}

	authorID, err := shared.IDFromString(input.AuthorID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid author id format", shared.ErrValidation)
	}

	oldStatus, err := vulnerability.ParseFindingStatus(input.OldStatus)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", shared.ErrValidation, err)
	}

	newStatus, err := vulnerability.ParseFindingStatus(input.NewStatus)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", shared.ErrValidation, err)
	}

	content := input.Content
	if content == "" {
		content = fmt.Sprintf("Status changed from %s to %s", oldStatus.String(), newStatus.String())
	}

	comment, err := vulnerability.NewStatusChangeComment(findingID, authorID, content, oldStatus, newStatus)
	if err != nil {
		return nil, err
	}

	if err := s.commentRepo.Create(ctx, comment); err != nil {
		return nil, fmt.Errorf("failed to create status change comment: %w", err)
	}

	s.logger.Info("status change comment added", "comment_id", comment.ID().String())
	return comment, nil
}

// GetComment retrieves a comment by ID.
func (s *FindingCommentService) GetComment(ctx context.Context, commentID string) (*vulnerability.FindingComment, error) {
	parsedID, err := shared.IDFromString(commentID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid id format", shared.ErrValidation)
	}

	return s.commentRepo.GetByID(ctx, parsedID)
}

// UpdateCommentInput represents the input for updating a comment.
type UpdateCommentInput struct {
	Content string `validate:"required,min=1,max=10000"`
}

// UpdateComment updates an existing comment.
func (s *FindingCommentService) UpdateComment(ctx context.Context, commentID, authorID string, input UpdateCommentInput) (*vulnerability.FindingComment, error) {
	parsedID, err := shared.IDFromString(commentID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid id format", shared.ErrValidation)
	}

	comment, err := s.commentRepo.GetByID(ctx, parsedID)
	if err != nil {
		return nil, err
	}

	// Only the author can update their comment
	if authorID != "" && comment.AuthorID().String() != authorID {
		return nil, fmt.Errorf("%w: only the author can update this comment", shared.ErrForbidden)
	}

	// Cannot edit status change comments
	if comment.IsStatusChange() {
		return nil, fmt.Errorf("%w: cannot edit status change comments", shared.ErrValidation)
	}

	if err := comment.UpdateContent(input.Content); err != nil {
		return nil, fmt.Errorf("failed to update content: %w", err)
	}

	if err := s.commentRepo.Update(ctx, comment); err != nil {
		return nil, fmt.Errorf("failed to update comment: %w", err)
	}

	s.logger.Info("comment updated", "comment_id", commentID)
	return comment, nil
}

// DeleteComment deletes a comment.
func (s *FindingCommentService) DeleteComment(ctx context.Context, commentID, authorID string) error {
	parsedID, err := shared.IDFromString(commentID)
	if err != nil {
		return fmt.Errorf("%w: invalid id format", shared.ErrValidation)
	}

	comment, err := s.commentRepo.GetByID(ctx, parsedID)
	if err != nil {
		return err
	}

	// Only the author can delete their comment (unless admin)
	if authorID != "" && comment.AuthorID().String() != authorID {
		return fmt.Errorf("%w: only the author can delete this comment", shared.ErrForbidden)
	}

	// Cannot delete status change comments
	if comment.IsStatusChange() {
		return fmt.Errorf("%w: cannot delete status change comments", shared.ErrValidation)
	}

	if err := s.commentRepo.Delete(ctx, parsedID); err != nil {
		return err
	}

	s.logger.Info("comment deleted", "comment_id", commentID)
	return nil
}

// ListFindingComments retrieves all comments for a finding.
func (s *FindingCommentService) ListFindingComments(ctx context.Context, findingID string) ([]*vulnerability.FindingComment, error) {
	parsedID, err := shared.IDFromString(findingID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid finding id format", shared.ErrValidation)
	}

	return s.commentRepo.ListByFinding(ctx, parsedID)
}

// CountFindingComments counts comments for a finding.
func (s *FindingCommentService) CountFindingComments(ctx context.Context, findingID string) (int, error) {
	parsedID, err := shared.IDFromString(findingID)
	if err != nil {
		return 0, fmt.Errorf("%w: invalid finding id format", shared.ErrValidation)
	}

	return s.commentRepo.CountByFinding(ctx, parsedID)
}
