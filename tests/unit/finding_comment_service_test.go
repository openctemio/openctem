package unit

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
	"github.com/openctemio/api/pkg/logger"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Mock: FindingCommentRepository
// =============================================================================

type mockFindingCommentServiceRepo struct {
	comments map[string]*vulnerability.FindingComment

	createErr error
	getErr    error
	updateErr error
	deleteErr error
	listErr   error
	countErr  error

	createCalls int
	getCalls    int
	updateCalls int
	deleteCalls int
	listCalls   int
	countCalls  int
}

func newMockFindingCommentServiceRepo() *mockFindingCommentServiceRepo {
	return &mockFindingCommentServiceRepo{
		comments: make(map[string]*vulnerability.FindingComment),
	}
}

func (m *mockFindingCommentServiceRepo) Create(_ context.Context, comment *vulnerability.FindingComment) error {
	m.createCalls++
	if m.createErr != nil {
		return m.createErr
	}
	m.comments[comment.ID().String()] = comment
	return nil
}

func (m *mockFindingCommentServiceRepo) GetByID(_ context.Context, id shared.ID) (*vulnerability.FindingComment, error) {
	m.getCalls++
	if m.getErr != nil {
		return nil, m.getErr
	}
	c, ok := m.comments[id.String()]
	if !ok {
		return nil, shared.ErrNotFound
	}
	return c, nil
}

func (m *mockFindingCommentServiceRepo) GetByTenantAndID(_ context.Context, _, id shared.ID) (*vulnerability.FindingComment, error) {
	m.getCalls++
	if m.getErr != nil {
		return nil, m.getErr
	}
	c, ok := m.comments[id.String()]
	if !ok {
		return nil, shared.ErrNotFound
	}
	return c, nil
}

func (m *mockFindingCommentServiceRepo) Update(_ context.Context, comment *vulnerability.FindingComment) error {
	m.updateCalls++
	if m.updateErr != nil {
		return m.updateErr
	}
	if _, ok := m.comments[comment.ID().String()]; !ok {
		return shared.ErrNotFound
	}
	m.comments[comment.ID().String()] = comment
	return nil
}

func (m *mockFindingCommentServiceRepo) Delete(_ context.Context, _, id shared.ID) error {
	m.deleteCalls++
	if m.deleteErr != nil {
		return m.deleteErr
	}
	if _, ok := m.comments[id.String()]; !ok {
		return shared.ErrNotFound
	}
	delete(m.comments, id.String())
	return nil
}

func (m *mockFindingCommentServiceRepo) ListByFinding(_ context.Context, findingID shared.ID) ([]*vulnerability.FindingComment, error) {
	m.listCalls++
	if m.listErr != nil {
		return nil, m.listErr
	}
	result := make([]*vulnerability.FindingComment, 0)
	for _, c := range m.comments {
		if c.FindingID() == findingID {
			result = append(result, c)
		}
	}
	return result, nil
}

func (m *mockFindingCommentServiceRepo) CountByFinding(_ context.Context, findingID shared.ID) (int, error) {
	m.countCalls++
	if m.countErr != nil {
		return 0, m.countErr
	}
	count := 0
	for _, c := range m.comments {
		if c.FindingID() == findingID {
			count++
		}
	}
	return count, nil
}

// =============================================================================
// Helpers
// =============================================================================

func newTestCommentService(commentRepo *mockFindingCommentServiceRepo, findingRepo *mockFindingRepo) *app.FindingCommentService {
	log := logger.NewNop()
	return app.NewFindingCommentService(commentRepo, findingRepo, log)
}

func makeTestComment(findingID, authorID shared.ID, content string, isStatusChange bool) *vulnerability.FindingComment {
	now := time.Now().UTC()
	oldStatus := vulnerability.FindingStatusNew
	newStatus := vulnerability.FindingStatusResolved
	if !isStatusChange {
		oldStatus = ""
		newStatus = ""
	}
	return vulnerability.ReconstituteFindingComment(
		shared.NewID(),
		shared.NewID(), // tenantID — mock is tenant-agnostic, a random UUID is fine
		findingID,
		authorID,
		"Test User",
		"test@example.com",
		content,
		isStatusChange,
		oldStatus,
		newStatus,
		now,
		now,
	)
}

// =============================================================================
// Tests: AddComment
// =============================================================================

func TestAddComment_Success(t *testing.T) {
	commentRepo := newMockFindingCommentServiceRepo()
	findingRepo := newMockFindingRepo()
	svc := newTestCommentService(commentRepo, findingRepo)

	tenantID := shared.NewID()
	findingID := shared.NewID()
	authorID := shared.NewID()

	f := createTestFindingForComment(tenantID, findingID)
	findingRepo.findings[findingID.String()] = f

	result, err := svc.AddComment(context.Background(), app.AddCommentInput{
		TenantID:  tenantID.String(),
		FindingID: findingID.String(),
		AuthorID:  authorID.String(),
		Content:   "This is a test comment",
	})

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, findingID, result.FindingID())
	assert.Equal(t, authorID, result.AuthorID())
	assert.Equal(t, "This is a test comment", result.Content())
	assert.False(t, result.IsStatusChange())
	assert.Equal(t, 1, commentRepo.createCalls)
}

func TestAddComment_InvalidTenantID(t *testing.T) {
	commentRepo := newMockFindingCommentServiceRepo()
	findingRepo := newMockFindingRepo()
	svc := newTestCommentService(commentRepo, findingRepo)

	result, err := svc.AddComment(context.Background(), app.AddCommentInput{
		TenantID:  "not-a-uuid",
		FindingID: shared.NewID().String(),
		AuthorID:  shared.NewID().String(),
		Content:   "comment",
	})

	require.Error(t, err)
	assert.Nil(t, result)
	assert.True(t, errors.Is(err, shared.ErrValidation))
	assert.Equal(t, 0, commentRepo.createCalls)
}

func TestAddComment_InvalidFindingID(t *testing.T) {
	commentRepo := newMockFindingCommentServiceRepo()
	findingRepo := newMockFindingRepo()
	svc := newTestCommentService(commentRepo, findingRepo)

	result, err := svc.AddComment(context.Background(), app.AddCommentInput{
		TenantID:  shared.NewID().String(),
		FindingID: "invalid",
		AuthorID:  shared.NewID().String(),
		Content:   "comment",
	})

	require.Error(t, err)
	assert.Nil(t, result)
	assert.True(t, errors.Is(err, shared.ErrValidation))
}

func TestAddComment_InvalidAuthorID(t *testing.T) {
	commentRepo := newMockFindingCommentServiceRepo()
	findingRepo := newMockFindingRepo()
	svc := newTestCommentService(commentRepo, findingRepo)

	result, err := svc.AddComment(context.Background(), app.AddCommentInput{
		TenantID:  shared.NewID().String(),
		FindingID: shared.NewID().String(),
		AuthorID:  "bad-uuid",
		Content:   "comment",
	})

	require.Error(t, err)
	assert.Nil(t, result)
	assert.True(t, errors.Is(err, shared.ErrValidation))
}

func TestAddComment_FindingNotFound(t *testing.T) {
	commentRepo := newMockFindingCommentServiceRepo()
	findingRepo := newMockFindingRepo()
	svc := newTestCommentService(commentRepo, findingRepo)

	result, err := svc.AddComment(context.Background(), app.AddCommentInput{
		TenantID:  shared.NewID().String(),
		FindingID: shared.NewID().String(),
		AuthorID:  shared.NewID().String(),
		Content:   "comment",
	})

	require.Error(t, err)
	assert.Nil(t, result)
	assert.True(t, errors.Is(err, shared.ErrNotFound))
	assert.Equal(t, 0, commentRepo.createCalls)
}

func TestAddComment_RepoCreateError(t *testing.T) {
	commentRepo := newMockFindingCommentServiceRepo()
	findingRepo := newMockFindingRepo()
	svc := newTestCommentService(commentRepo, findingRepo)

	tenantID := shared.NewID()
	findingID := shared.NewID()

	f := createTestFindingForComment(tenantID, findingID)
	findingRepo.findings[findingID.String()] = f
	commentRepo.createErr = errors.New("database error")

	result, err := svc.AddComment(context.Background(), app.AddCommentInput{
		TenantID:  tenantID.String(),
		FindingID: findingID.String(),
		AuthorID:  shared.NewID().String(),
		Content:   "comment",
	})

	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "failed to create comment")
}

// =============================================================================
// Tests: AddStatusChangeComment
// =============================================================================

func TestAddStatusChangeComment_Success(t *testing.T) {
	commentRepo := newMockFindingCommentServiceRepo()
	findingRepo := newMockFindingRepo()
	svc := newTestCommentService(commentRepo, findingRepo)

	result, err := svc.AddStatusChangeComment(context.Background(), app.AddStatusChangeCommentInput{
		TenantID:  shared.NewID().String(),
		FindingID: shared.NewID().String(),
		AuthorID:  shared.NewID().String(),
		Content:   "Marking as resolved",
		OldStatus: "new",
		NewStatus: "resolved",
	})

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.IsStatusChange())
	assert.Equal(t, "Marking as resolved", result.Content())
	assert.Equal(t, 1, commentRepo.createCalls)
}

func TestAddStatusChangeComment_WithCustomContent(t *testing.T) {
	commentRepo := newMockFindingCommentServiceRepo()
	findingRepo := newMockFindingRepo()
	svc := newTestCommentService(commentRepo, findingRepo)

	customContent := "Fixed in PR #123"
	result, err := svc.AddStatusChangeComment(context.Background(), app.AddStatusChangeCommentInput{
		TenantID:  shared.NewID().String(),
		FindingID: shared.NewID().String(),
		AuthorID:  shared.NewID().String(),
		Content:   customContent,
		OldStatus: "confirmed",
		NewStatus: "in_progress",
	})

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, customContent, result.Content())
	assert.True(t, result.IsStatusChange())
}

func TestAddStatusChangeComment_AutoGenerateContent(t *testing.T) {
	commentRepo := newMockFindingCommentServiceRepo()
	findingRepo := newMockFindingRepo()
	svc := newTestCommentService(commentRepo, findingRepo)

	result, err := svc.AddStatusChangeComment(context.Background(), app.AddStatusChangeCommentInput{
		TenantID:  shared.NewID().String(),
		FindingID: shared.NewID().String(),
		AuthorID:  shared.NewID().String(),
		Content:   "", // empty content triggers auto-generation
		OldStatus: "new",
		NewStatus: "resolved",
	})

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "Status changed from new to resolved", result.Content())
	assert.True(t, result.IsStatusChange())
}

func TestAddStatusChangeComment_InvalidFindingID(t *testing.T) {
	commentRepo := newMockFindingCommentServiceRepo()
	findingRepo := newMockFindingRepo()
	svc := newTestCommentService(commentRepo, findingRepo)

	result, err := svc.AddStatusChangeComment(context.Background(), app.AddStatusChangeCommentInput{
		TenantID:  shared.NewID().String(),
		FindingID: "bad-id",
		AuthorID:  shared.NewID().String(),
		Content:   "test",
		OldStatus: "new",
		NewStatus: "resolved",
	})

	require.Error(t, err)
	assert.Nil(t, result)
	assert.True(t, errors.Is(err, shared.ErrValidation))
}

func TestAddStatusChangeComment_InvalidAuthorID(t *testing.T) {
	commentRepo := newMockFindingCommentServiceRepo()
	findingRepo := newMockFindingRepo()
	svc := newTestCommentService(commentRepo, findingRepo)

	result, err := svc.AddStatusChangeComment(context.Background(), app.AddStatusChangeCommentInput{
		TenantID:  shared.NewID().String(),
		FindingID: shared.NewID().String(),
		AuthorID:  "not-valid",
		Content:   "test",
		OldStatus: "new",
		NewStatus: "resolved",
	})

	require.Error(t, err)
	assert.Nil(t, result)
	assert.True(t, errors.Is(err, shared.ErrValidation))
}

func TestAddStatusChangeComment_InvalidOldStatus(t *testing.T) {
	commentRepo := newMockFindingCommentServiceRepo()
	findingRepo := newMockFindingRepo()
	svc := newTestCommentService(commentRepo, findingRepo)

	result, err := svc.AddStatusChangeComment(context.Background(), app.AddStatusChangeCommentInput{
		TenantID:  shared.NewID().String(),
		FindingID: shared.NewID().String(),
		AuthorID:  shared.NewID().String(),
		Content:   "test",
		OldStatus: "nonexistent_status",
		NewStatus: "resolved",
	})

	require.Error(t, err)
	assert.Nil(t, result)
	assert.True(t, errors.Is(err, shared.ErrValidation))
}

func TestAddStatusChangeComment_InvalidNewStatus(t *testing.T) {
	commentRepo := newMockFindingCommentServiceRepo()
	findingRepo := newMockFindingRepo()
	svc := newTestCommentService(commentRepo, findingRepo)

	result, err := svc.AddStatusChangeComment(context.Background(), app.AddStatusChangeCommentInput{
		TenantID:  shared.NewID().String(),
		FindingID: shared.NewID().String(),
		AuthorID:  shared.NewID().String(),
		Content:   "test",
		OldStatus: "new",
		NewStatus: "bogus",
	})

	require.Error(t, err)
	assert.Nil(t, result)
	assert.True(t, errors.Is(err, shared.ErrValidation))
}

func TestAddStatusChangeComment_RepoError(t *testing.T) {
	commentRepo := newMockFindingCommentServiceRepo()
	findingRepo := newMockFindingRepo()
	svc := newTestCommentService(commentRepo, findingRepo)

	commentRepo.createErr = errors.New("db write failed")

	result, err := svc.AddStatusChangeComment(context.Background(), app.AddStatusChangeCommentInput{
		TenantID:  shared.NewID().String(),
		FindingID: shared.NewID().String(),
		AuthorID:  shared.NewID().String(),
		Content:   "test",
		OldStatus: "new",
		NewStatus: "resolved",
	})

	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "failed to create status change comment")
}

// =============================================================================
// Tests: GetComment
// =============================================================================

func TestGetComment_Success(t *testing.T) {
	commentRepo := newMockFindingCommentServiceRepo()
	findingRepo := newMockFindingRepo()
	svc := newTestCommentService(commentRepo, findingRepo)

	findingID := shared.NewID()
	authorID := shared.NewID()
	comment := makeTestComment(findingID, authorID, "existing comment", false)
	commentRepo.comments[comment.ID().String()] = comment

	result, err := svc.GetComment(context.Background(), comment.ID().String())

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, comment.ID(), result.ID())
	assert.Equal(t, "existing comment", result.Content())
}

func TestGetComment_InvalidID(t *testing.T) {
	commentRepo := newMockFindingCommentServiceRepo()
	findingRepo := newMockFindingRepo()
	svc := newTestCommentService(commentRepo, findingRepo)

	result, err := svc.GetComment(context.Background(), "not-a-uuid")

	require.Error(t, err)
	assert.Nil(t, result)
	assert.True(t, errors.Is(err, shared.ErrValidation))
}

func TestGetComment_NotFound(t *testing.T) {
	commentRepo := newMockFindingCommentServiceRepo()
	findingRepo := newMockFindingRepo()
	svc := newTestCommentService(commentRepo, findingRepo)

	result, err := svc.GetComment(context.Background(), shared.NewID().String())

	require.Error(t, err)
	assert.Nil(t, result)
	assert.True(t, errors.Is(err, shared.ErrNotFound))
}

// =============================================================================
// Tests: UpdateComment
// =============================================================================

func TestUpdateComment_Success(t *testing.T) {
	commentRepo := newMockFindingCommentServiceRepo()
	findingRepo := newMockFindingRepo()
	svc := newTestCommentService(commentRepo, findingRepo)

	authorID := shared.NewID()
	comment := makeTestComment(shared.NewID(), authorID, "original content", false)
	commentRepo.comments[comment.ID().String()] = comment

	result, err := svc.UpdateComment(context.Background(), shared.NewID().String(), comment.ID().String(), authorID.String(), app.UpdateCommentInput{
		Content: "updated content",
	})

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "updated content", result.Content())
	assert.Equal(t, 1, commentRepo.updateCalls)
}

func TestUpdateComment_NotFound(t *testing.T) {
	commentRepo := newMockFindingCommentServiceRepo()
	findingRepo := newMockFindingRepo()
	svc := newTestCommentService(commentRepo, findingRepo)

	result, err := svc.UpdateComment(context.Background(), shared.NewID().String(), shared.NewID().String(), shared.NewID().String(), app.UpdateCommentInput{
		Content: "test",
	})

	require.Error(t, err)
	assert.Nil(t, result)
	assert.True(t, errors.Is(err, shared.ErrNotFound))
}

func TestUpdateComment_WrongAuthor(t *testing.T) {
	commentRepo := newMockFindingCommentServiceRepo()
	findingRepo := newMockFindingRepo()
	svc := newTestCommentService(commentRepo, findingRepo)

	authorID := shared.NewID()
	otherUserID := shared.NewID()
	comment := makeTestComment(shared.NewID(), authorID, "my comment", false)
	commentRepo.comments[comment.ID().String()] = comment

	result, err := svc.UpdateComment(context.Background(), shared.NewID().String(), comment.ID().String(), otherUserID.String(), app.UpdateCommentInput{
		Content: "hijacked",
	})

	require.Error(t, err)
	assert.Nil(t, result)
	assert.True(t, errors.Is(err, shared.ErrForbidden))
	assert.Equal(t, 0, commentRepo.updateCalls)
}

func TestUpdateComment_StatusChangeComment(t *testing.T) {
	commentRepo := newMockFindingCommentServiceRepo()
	findingRepo := newMockFindingRepo()
	svc := newTestCommentService(commentRepo, findingRepo)

	authorID := shared.NewID()
	comment := makeTestComment(shared.NewID(), authorID, "Status changed", true)
	commentRepo.comments[comment.ID().String()] = comment

	result, err := svc.UpdateComment(context.Background(), shared.NewID().String(), comment.ID().String(), authorID.String(), app.UpdateCommentInput{
		Content: "trying to edit status change",
	})

	require.Error(t, err)
	assert.Nil(t, result)
	assert.True(t, errors.Is(err, shared.ErrValidation))
	assert.Contains(t, err.Error(), "cannot edit status change comments")
	assert.Equal(t, 0, commentRepo.updateCalls)
}

func TestUpdateComment_RepoUpdateError(t *testing.T) {
	commentRepo := newMockFindingCommentServiceRepo()
	findingRepo := newMockFindingRepo()
	svc := newTestCommentService(commentRepo, findingRepo)

	authorID := shared.NewID()
	comment := makeTestComment(shared.NewID(), authorID, "content", false)
	commentRepo.comments[comment.ID().String()] = comment
	commentRepo.updateErr = errors.New("update failed")

	result, err := svc.UpdateComment(context.Background(), shared.NewID().String(), comment.ID().String(), authorID.String(), app.UpdateCommentInput{
		Content: "new content",
	})

	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "failed to update comment")
}

// =============================================================================
// Tests: DeleteComment
// =============================================================================

func TestDeleteComment_Success(t *testing.T) {
	commentRepo := newMockFindingCommentServiceRepo()
	findingRepo := newMockFindingRepo()
	svc := newTestCommentService(commentRepo, findingRepo)

	authorID := shared.NewID()
	comment := makeTestComment(shared.NewID(), authorID, "to be deleted", false)
	commentRepo.comments[comment.ID().String()] = comment

	err := svc.DeleteComment(context.Background(), shared.NewID().String(), comment.ID().String(), authorID.String())

	require.NoError(t, err)
	assert.Equal(t, 1, commentRepo.deleteCalls)
	_, exists := commentRepo.comments[comment.ID().String()]
	assert.False(t, exists)
}

func TestDeleteComment_InvalidID(t *testing.T) {
	commentRepo := newMockFindingCommentServiceRepo()
	findingRepo := newMockFindingRepo()
	svc := newTestCommentService(commentRepo, findingRepo)

	err := svc.DeleteComment(context.Background(), shared.NewID().String(), "bad-uuid", shared.NewID().String())

	require.Error(t, err)
	assert.True(t, errors.Is(err, shared.ErrValidation))
}

func TestDeleteComment_NotFound(t *testing.T) {
	commentRepo := newMockFindingCommentServiceRepo()
	findingRepo := newMockFindingRepo()
	svc := newTestCommentService(commentRepo, findingRepo)

	err := svc.DeleteComment(context.Background(), shared.NewID().String(), shared.NewID().String(), shared.NewID().String())

	require.Error(t, err)
	assert.True(t, errors.Is(err, shared.ErrNotFound))
}

func TestDeleteComment_WrongAuthor(t *testing.T) {
	commentRepo := newMockFindingCommentServiceRepo()
	findingRepo := newMockFindingRepo()
	svc := newTestCommentService(commentRepo, findingRepo)

	authorID := shared.NewID()
	otherUserID := shared.NewID()
	comment := makeTestComment(shared.NewID(), authorID, "my comment", false)
	commentRepo.comments[comment.ID().String()] = comment

	err := svc.DeleteComment(context.Background(), shared.NewID().String(), comment.ID().String(), otherUserID.String())

	require.Error(t, err)
	assert.True(t, errors.Is(err, shared.ErrForbidden))
	assert.Equal(t, 0, commentRepo.deleteCalls)
}

func TestDeleteComment_StatusChangeComment(t *testing.T) {
	commentRepo := newMockFindingCommentServiceRepo()
	findingRepo := newMockFindingRepo()
	svc := newTestCommentService(commentRepo, findingRepo)

	authorID := shared.NewID()
	comment := makeTestComment(shared.NewID(), authorID, "Status changed", true)
	commentRepo.comments[comment.ID().String()] = comment

	err := svc.DeleteComment(context.Background(), shared.NewID().String(), comment.ID().String(), authorID.String())

	require.Error(t, err)
	assert.True(t, errors.Is(err, shared.ErrValidation))
	assert.Contains(t, err.Error(), "cannot delete status change comments")
	assert.Equal(t, 0, commentRepo.deleteCalls)
}

func TestDeleteComment_RepoDeleteError(t *testing.T) {
	commentRepo := newMockFindingCommentServiceRepo()
	findingRepo := newMockFindingRepo()
	svc := newTestCommentService(commentRepo, findingRepo)

	authorID := shared.NewID()
	comment := makeTestComment(shared.NewID(), authorID, "content", false)
	commentRepo.comments[comment.ID().String()] = comment
	commentRepo.deleteErr = errors.New("delete failed")

	err := svc.DeleteComment(context.Background(), shared.NewID().String(), comment.ID().String(), authorID.String())

	require.Error(t, err)
	assert.Contains(t, err.Error(), "delete failed")
}

// =============================================================================
// Tests: ListFindingComments
// =============================================================================

func TestListFindingComments_Success(t *testing.T) {
	commentRepo := newMockFindingCommentServiceRepo()
	findingRepo := newMockFindingRepo()
	svc := newTestCommentService(commentRepo, findingRepo)

	findingID := shared.NewID()
	c1 := makeTestComment(findingID, shared.NewID(), "comment 1", false)
	c2 := makeTestComment(findingID, shared.NewID(), "comment 2", false)
	otherFindingComment := makeTestComment(shared.NewID(), shared.NewID(), "other finding", false)

	commentRepo.comments[c1.ID().String()] = c1
	commentRepo.comments[c2.ID().String()] = c2
	commentRepo.comments[otherFindingComment.ID().String()] = otherFindingComment

	result, err := svc.ListFindingComments(context.Background(), findingID.String())

	require.NoError(t, err)
	assert.Len(t, result, 2)
	assert.Equal(t, 1, commentRepo.listCalls)
}

func TestListFindingComments_InvalidFindingID(t *testing.T) {
	commentRepo := newMockFindingCommentServiceRepo()
	findingRepo := newMockFindingRepo()
	svc := newTestCommentService(commentRepo, findingRepo)

	result, err := svc.ListFindingComments(context.Background(), "not-a-uuid")

	require.Error(t, err)
	assert.Nil(t, result)
	assert.True(t, errors.Is(err, shared.ErrValidation))
}

func TestListFindingComments_RepoError(t *testing.T) {
	commentRepo := newMockFindingCommentServiceRepo()
	findingRepo := newMockFindingRepo()
	svc := newTestCommentService(commentRepo, findingRepo)

	commentRepo.listErr = errors.New("list failed")

	result, err := svc.ListFindingComments(context.Background(), shared.NewID().String())

	require.Error(t, err)
	assert.Nil(t, result)
}

// =============================================================================
// Tests: CountFindingComments
// =============================================================================

func TestCountFindingComments_Success(t *testing.T) {
	commentRepo := newMockFindingCommentServiceRepo()
	findingRepo := newMockFindingRepo()
	svc := newTestCommentService(commentRepo, findingRepo)

	findingID := shared.NewID()
	c1 := makeTestComment(findingID, shared.NewID(), "comment 1", false)
	c2 := makeTestComment(findingID, shared.NewID(), "comment 2", false)
	commentRepo.comments[c1.ID().String()] = c1
	commentRepo.comments[c2.ID().String()] = c2

	count, err := svc.CountFindingComments(context.Background(), findingID.String())

	require.NoError(t, err)
	assert.Equal(t, 2, count)
	assert.Equal(t, 1, commentRepo.countCalls)
}

func TestCountFindingComments_InvalidFindingID(t *testing.T) {
	commentRepo := newMockFindingCommentServiceRepo()
	findingRepo := newMockFindingRepo()
	svc := newTestCommentService(commentRepo, findingRepo)

	count, err := svc.CountFindingComments(context.Background(), "invalid-uuid")

	require.Error(t, err)
	assert.Equal(t, 0, count)
	assert.True(t, errors.Is(err, shared.ErrValidation))
}

func TestCountFindingComments_RepoError(t *testing.T) {
	commentRepo := newMockFindingCommentServiceRepo()
	findingRepo := newMockFindingRepo()
	svc := newTestCommentService(commentRepo, findingRepo)

	commentRepo.countErr = errors.New("count failed")

	count, err := svc.CountFindingComments(context.Background(), shared.NewID().String())

	require.Error(t, err)
	assert.Equal(t, 0, count)
}

// =============================================================================
// Helper: createTestFindingForComment
// =============================================================================

func createTestFindingForComment(tenantID, findingID shared.ID) *vulnerability.Finding {
	now := time.Now().UTC()
	return vulnerability.ReconstituteFinding(vulnerability.FindingData{
		ID:          findingID,
		TenantID:    tenantID,
		AssetID:     shared.NewID(),
		Source:      vulnerability.FindingSourceSAST,
		ToolName:    "test-tool",
		Title:       "Test Finding",
		Severity:    vulnerability.SeverityHigh,
		Status:      vulnerability.FindingStatusNew,
		Fingerprint: "fp-" + findingID.String(),
		CreatedAt:   now,
		UpdatedAt:   now,
	})
}
