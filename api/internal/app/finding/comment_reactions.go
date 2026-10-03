package finding

import (
	"context"
	"fmt"

	"github.com/openctemio/openctem/api/internal/app/audit"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// AuditLogger writes audit events. Implemented by *audit.AuditService.
type AuditLogger interface {
	LogEvent(ctx context.Context, actx audit.AuditContext, event audit.AuditEvent) error
}

// SetAuditService wires the audit trail for comment moderation (an admin
// removing someone else's reaction). Nil leaves it unaudited.
func (s *VulnerabilityService) SetAuditService(a AuditLogger) {
	s.auditService = a
}

// SetCommentReactionRepository enables emoji reactions on finding comments.
func (s *VulnerabilityService) SetCommentReactionRepository(repo vulnerability.CommentReactionRepository) {
	s.reactionRepo = repo
}

// CommentReactionInput is one reaction change on a finding comment.
type CommentReactionInput struct {
	TenantID  string
	CommentID string
	Emoji     string
	// UserID is the caller's local user id: the reactor.
	UserID string
	// ActingUserID is the authenticated subject, used for pentest campaign
	// membership (the same identity the comment list checks).
	ActingUserID string
	IsAdmin      bool
	// TargetUserID, on remove, names someone else's reaction to remove. Only
	// an organization admin or owner may do that, and it is audited. Empty
	// (or the caller's own id) removes the caller's reaction.
	TargetUserID string
	// Audit describes the request for the moderation audit entry.
	Audit audit.AuditContext
}

// reactionTarget is a validated reaction request.
type reactionTarget struct {
	tenantID shared.ID
	comment  *vulnerability.FindingComment
	userID   shared.ID
	emoji    string
}

// resolveReaction validates the input and authorizes the caller: the comment
// must belong to the caller's tenant (another tenant's comment is not found)
// and the caller must be allowed to read the comment's finding.
func (s *VulnerabilityService) resolveReaction(ctx context.Context, in CommentReactionInput) (*reactionTarget, error) {
	if s.commentRepo == nil || s.reactionRepo == nil {
		return nil, fmt.Errorf("%w: comment reactions are not configured", shared.ErrValidation)
	}
	tenantID, err := shared.IDFromString(in.TenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id format", shared.ErrValidation)
	}
	commentID, err := shared.IDFromString(in.CommentID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid comment id format", shared.ErrValidation)
	}
	userID, err := shared.IDFromString(in.UserID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid user id format", shared.ErrValidation)
	}
	emoji, err := vulnerability.NormalizeReactionEmoji(in.Emoji)
	if err != nil {
		return nil, err
	}
	comment, err := s.commentRepo.GetByTenantAndID(ctx, tenantID, commentID)
	if err != nil {
		return nil, err
	}
	if err := s.authorizeCommentFinding(ctx, tenantID, comment.FindingID(), in.ActingUserID, in.IsAdmin); err != nil {
		return nil, err
	}
	return &reactionTarget{tenantID: tenantID, comment: comment, userID: userID, emoji: emoji}, nil
}

// AddCommentReaction adds the caller's reaction to a comment and returns the
// comment's reactions. Adding a reaction that already exists changes nothing.
func (s *VulnerabilityService) AddCommentReaction(ctx context.Context, in CommentReactionInput) ([]vulnerability.ReactionSummary, error) {
	t, err := s.resolveReaction(ctx, in)
	if err != nil {
		return nil, err
	}
	added, err := s.reactionRepo.Add(ctx, t.tenantID, t.comment.ID(), t.userID, t.emoji)
	if err != nil {
		return nil, err
	}
	if added {
		s.activityService.BroadcastCommentReactionsUpdated(t.tenantID, t.comment.FindingID(), t.comment.ID())
	}
	return s.commentReactions(ctx, t.tenantID, t.comment.ID(), t.userID)
}

// RemoveCommentReaction removes a reaction and returns the comment's
// reactions. Removing a reaction that does not exist changes nothing.
func (s *VulnerabilityService) RemoveCommentReaction(ctx context.Context, in CommentReactionInput) ([]vulnerability.ReactionSummary, error) {
	t, err := s.resolveReaction(ctx, in)
	if err != nil {
		return nil, err
	}

	owner := t.userID
	moderating := false
	if in.TargetUserID != "" && in.TargetUserID != in.UserID {
		if !in.IsAdmin {
			return nil, fmt.Errorf("%w: only an organization admin can remove another member's reaction", shared.ErrForbidden)
		}
		target, err := shared.IDFromString(in.TargetUserID)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid user id format", shared.ErrValidation)
		}
		owner = target
		moderating = true
	}

	removed, err := s.reactionRepo.Remove(ctx, t.tenantID, t.comment.ID(), owner, t.emoji)
	if err != nil {
		return nil, err
	}
	if removed {
		if moderating {
			s.auditReactionRemoval(ctx, in.Audit, t, owner)
		}
		s.activityService.BroadcastCommentReactionsUpdated(t.tenantID, t.comment.FindingID(), t.comment.ID())
	}
	return s.commentReactions(ctx, t.tenantID, t.comment.ID(), t.userID)
}

func (s *VulnerabilityService) auditReactionRemoval(ctx context.Context, actx audit.AuditContext, t *reactionTarget, owner shared.ID) {
	if s.auditService == nil {
		return
	}
	if actx.TenantID == "" {
		actx.TenantID = t.tenantID.String()
	}
	event := audit.NewSuccessEvent(auditdom.ActionFindingCommentReactionRemoved,
		auditdom.ResourceTypeFindingComment, t.comment.ID().String()).
		WithMessage("Removed a member's reaction from a finding comment").
		WithMetadata("finding_id", t.comment.FindingID().String()).
		WithMetadata("reaction_user_id", owner.String()).
		WithMetadata("emoji", t.emoji).
		WithSeverity(auditdom.SeverityLow)
	if err := s.auditService.LogEvent(ctx, actx, event); err != nil {
		s.logger.Warn("failed to audit reaction removal", "error", err)
	}
}

func (s *VulnerabilityService) commentReactions(ctx context.Context, tenantID, commentID, viewerID shared.ID) ([]vulnerability.ReactionSummary, error) {
	all, err := s.reactionRepo.Summaries(ctx, tenantID, []shared.ID{commentID}, viewerID)
	if err != nil {
		return nil, err
	}
	if r := all[commentID]; r != nil {
		return r, nil
	}
	return []vulnerability.ReactionSummary{}, nil
}

// CommentReactionSummaries returns the reactions of each comment in one
// query, keyed by comment id. The caller has already been authorized for the
// comments (it listed, created or updated them). viewerID drives
// ReactedByMe. Without a reaction repository the map is empty.
func (s *VulnerabilityService) CommentReactionSummaries(ctx context.Context, tenantID string, commentIDs []shared.ID, viewerID string) (map[shared.ID][]vulnerability.ReactionSummary, error) {
	if s.reactionRepo == nil || len(commentIDs) == 0 {
		return map[shared.ID][]vulnerability.ReactionSummary{}, nil
	}
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id format", shared.ErrValidation)
	}
	// An unparseable viewer simply has no reactions of their own.
	vid, _ := shared.IDFromString(viewerID)
	return s.reactionRepo.Summaries(ctx, tid, commentIDs, vid)
}
