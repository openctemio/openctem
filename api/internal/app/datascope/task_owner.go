package datascope

import (
	"context"
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// TaskOwnerReader is the optional storage question "which of these findings
// are in a live task this user owns" (postgres.DataScopeRepository). A
// repository without it grants nothing through task ownership.
type TaskOwnerReader interface {
	// FindingIDsOwnedViaTask returns the subset of findingIDs (in the tenant)
	// that are active primary members of a live task the user owns, directly
	// or as an active member of the owner team, on an asset not hidden from
	// them. Pentest findings are never returned.
	FindingIDsOwnedViaTask(ctx context.Context, tenantID, userID shared.ID, findingIDs []shared.ID) ([]shared.ID, error)
}

// OwnedViaTask returns a predicate over finding ids: the user owns a live
// task holding the finding (the task-owner relation of the fix workflow, D24
// of research 217). It is evaluated per call, so it ends the moment the
// owner changes, the finding leaves the task, the task closes or the team
// membership ends. A repository without TaskOwnerReader answers false.
func (e *Enforcer) OwnedViaTask(ctx context.Context, tenantID, userID shared.ID, findingIDs []shared.ID) (func(shared.ID) bool, error) {
	none := func(shared.ID) bool { return false }
	if e == nil || e.repo == nil || len(findingIDs) == 0 || userID.IsZero() {
		return none, nil
	}
	r, ok := e.repo.(TaskOwnerReader)
	if !ok {
		return none, nil
	}
	in, err := r.FindingIDsOwnedViaTask(ctx, tenantID, userID, dedupe(findingIDs))
	if err != nil {
		return none, fmt.Errorf("check task ownership: %w", err)
	}
	return setOf(in), nil
}

// callerOwnsViaTask is the relation for the request's caller: false for a
// request with no user and for an API key (a key acts with its own scope,
// never with the holder's task ownership).
func (e *Enforcer) callerOwnsViaTask(ctx context.Context, tenantID, findingID shared.ID) bool {
	c := e.CallerOf(ctx)
	if c.UserID == "" || c.APIKey {
		return false
	}
	uid, err := shared.IDFromString(c.UserID)
	if err != nil {
		return false
	}
	in, err := e.OwnedViaTask(ctx, tenantID, uid, []shared.ID{findingID})
	if err != nil {
		e.logger.Warn("task ownership check failed", "error", err)
		return false
	}
	return in(findingID)
}

// AssertFindingForFixWork is AssertFinding for a route of the fix workflow
// (read, comment, claim, evidence, request verification): a finding outside
// the caller's scope is still admitted when the caller owns a live task
// holding it. viaTask reports that the relation, not the scope, admitted
// the caller. ErrNotFound otherwise.
func (e *Enforcer) AssertFindingForFixWork(ctx context.Context, tenantID, findingID shared.ID) (viaTask bool, err error) {
	if err := e.AssertFinding(ctx, tenantID, findingID); err == nil {
		return false, nil
	}
	if e.callerOwnsViaTask(ctx, tenantID, findingID) {
		return true, nil
	}
	return false, shared.ErrNotFound
}

// TaskOwnerMay reports whether the request was admitted by the guard through
// the task-owner relation and the caller still owns a live task holding the
// finding. Services that apply the data scope again call it, so the relation
// widens only the routes the guard marked.
func (e *Enforcer) TaskOwnerMay(ctx context.Context, tenantID, findingID shared.ID) bool {
	return shared.TaskOwnerView(ctx) && e.callerOwnsViaTask(ctx, tenantID, findingID)
}
