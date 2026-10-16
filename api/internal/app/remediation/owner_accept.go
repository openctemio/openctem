package remediation

// Accepting a suggestion as the asset owner, without findings:remediation:write
// (docs/rfcs/RFC-098-remediation-tasks.md §6, owner decision D10).
//
// An owner may accept, as it is, a suggestion that only routes their own
// findings to them: a join into a task assigned to them (or to one of their
// groups) or a new task under an existing fix for them. They cannot start a
// new fix, edit the suggestion, leave findings out (that is remembered for
// the key, for everyone) or turn on auto-join. Every finding must be in their
// data scope (the suggestion has no hidden members) and on an asset they own
// as primary or secondary owner, directly or through a group.

import (
	"context"
	"fmt"

	remediationdom "github.com/openctemio/openctem/api/pkg/domain/remediation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Owner accept refusals.
var (
	ErrOwnerAcceptKind  = fmt.Errorf("%w: without remediation write access you can accept only a suggestion that adds your findings to your task or creates a task for you", shared.ErrForbidden)
	ErrOwnerAcceptAsIs  = fmt.Errorf("%w: without remediation write access a suggestion is accepted as it is (no edits, no removed findings, no auto-join)", shared.ErrForbidden)
	ErrOwnerAcceptOwner = fmt.Errorf("%w: the suggestion is not for you or one of your groups", shared.ErrForbidden)
	ErrOwnerAcceptAsset = fmt.Errorf("%w: every finding of the suggestion must be on an asset you own", shared.ErrForbidden)
)

// checkOwnerAccept decides whether a caller without write access may accept
// the suggestion as its owner.
func (s *SuggestionService) checkOwnerAccept(ctx context.Context, in AcceptInput, sg *remediationdom.Suggestion) error {
	if in.ActorID == nil || s.tasks == nil {
		return ErrOwnerAcceptOwner
	}
	if in.Title != nil || len(in.Exclude) > 0 || len(in.Owners) > 0 || in.Deadline != nil || in.AutoJoin {
		return ErrOwnerAcceptAsIs
	}
	var owners []remediationdom.Owner
	switch sg.Kind {
	case remediationdom.SuggestionJoin:
		if sg.TargetTaskID == nil {
			return ErrOwnerAcceptKind
		}
		t, err := s.tasks.writableTask(ctx, in.TenantID, *sg.TargetTaskID)
		if err != nil {
			return err
		}
		owners = []remediationdom.Owner{{UserID: t.AssigneeUserID, GroupID: t.AssigneeGroupID}}
	case remediationdom.SuggestionTaskRoute:
		for _, p := range sg.Partitions {
			owners = append(owners, p.Owner)
		}
	default:
		return ErrOwnerAcceptKind
	}
	if len(owners) == 0 {
		return ErrOwnerAcceptOwner
	}
	for _, o := range owners {
		ok, err := s.isOwner(ctx, in.TenantID, *in.ActorID, o)
		if err != nil {
			return err
		}
		if !ok {
			return ErrOwnerAcceptOwner
		}
	}
	owned, err := s.repo.OwnsFindingAssets(ctx, in.TenantID, *in.ActorID, sg.FindingIDs)
	if err != nil {
		return err
	}
	if !owned {
		return ErrOwnerAcceptAsset
	}
	return nil
}

// isOwner reports whether the user is the owner or belongs to its group.
func (s *SuggestionService) isOwner(ctx context.Context, tenantID, userID shared.ID, o remediationdom.Owner) (bool, error) {
	if o.UserID != nil && *o.UserID == userID {
		return true, nil
	}
	if o.GroupID != nil {
		return s.repo.IsGroupMember(ctx, tenantID, *o.GroupID, userID)
	}
	return false, nil
}
