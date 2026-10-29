package scope

// Adding many scope entries in one request (RFC-054 §14): a pasted list, a
// selection of inventory assets, or the targets a scan refused. Each item is
// an ordinary CreateTarget (guardrails, duplicates, the Strict request and
// approval rules, the signer ledger before the database write, the scope
// join), so a batch can never do more than the same entries added one by one.
// What the batch changes is the friction around it: one step-up check before
// anything is written, one notice to the administrators for the whole batch,
// and a result per item instead of the first error.

import (
	"context"
	"errors"
	"fmt"
	"strings"

	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// MaxBulkTargets is the most entries one bulk request may add (the dry run's
// limit, so a scan's refused targets always fit in one request).
const MaxBulkTargets = 200

// BulkTargetItem is one entry of a bulk add.
type BulkTargetItem struct {
	TargetType string
	Pattern    string
}

// BulkTargetsInput is a bulk add: the items and what they share.
type BulkTargetsInput struct {
	TenantID  string
	Items     []BulkTargetItem
	Reason    string
	CreatedBy string
	Actor     Actor
	// Origin is import (the default: a pasted list or a selection),
	// refusal_fix (the targets a scan refused), confirmed_asset (a person
	// confirmed the assets as the organization's) or connector (a connector
	// synced them); the last two are set by the server only.
	Origin scopedom.Origin
	// ExpiresInDays and MaxTier apply to every item of the batch, as they
	// would on POST /scope/targets (nil / empty: the entry point's defaults:
	// permanent, the organization's default tier). Each item still goes
	// through CreateTarget's policy checks.
	ExpiresInDays *int
	MaxTier       string
}

// BulkTargetOutcome is what happened to one item: Target is the entry it
// created, or Err why it was not created. A *scopedom.DuplicateError means
// the tenant already has the entry (Err names it).
type BulkTargetOutcome struct {
	Item   BulkTargetItem
	Target *scopedom.Target
	Err    error
}

// ErrBulkTargetsEmpty and ErrBulkTargetsTooMany bound a bulk add.
var (
	ErrBulkTargetsEmpty   = shared.NewDomainError("BULK_EMPTY", "Add at least one scope entry", shared.ErrValidation)
	ErrBulkTargetsTooMany = shared.NewDomainError("BULK_TOO_MANY", fmt.Sprintf("Add at most %d scope entries at once", MaxBulkTargets), shared.ErrValidation)
)

// CreateTargets adds each item as a scope entry. A request-level error
// (bad tenant, too many items, step-up missing) writes nothing; otherwise
// every item has an outcome, in order. Duplicate items within the request
// are answered by the first one's outcome's entry as a duplicate.
func (s *Service) CreateTargets(ctx context.Context, in BulkTargetsInput) ([]BulkTargetOutcome, error) {
	tenantID, err := shared.IDFromString(in.TenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	switch {
	case len(in.Items) == 0:
		return nil, ErrBulkTargetsEmpty
	case len(in.Items) > MaxBulkTargets:
		return nil, ErrBulkTargetsTooMany
	}
	origin := in.Origin
	if origin != scopedom.OriginRefusalFix && origin != scopedom.OriginConfirmed && origin != scopedom.OriginConnector {
		origin = scopedom.OriginImport
	}

	// A person who widens directly re-authenticates once for the batch,
	// before anything is written (CreateTarget asks again per item, inside
	// the same window). A Strict member's items are requests: no step-up.
	if !in.Actor.system() {
		p, err := s.loadPolicy(ctx, tenantID)
		if err != nil {
			return nil, err
		}
		if in.Actor.mayWiden(p.twoPerson()) {
			if err := s.requireStepUp(ctx, in.Actor); err != nil {
				return nil, err
			}
		}
	}

	out := make([]BulkTargetOutcome, 0, len(in.Items))
	var added []*scopedom.Target
	for _, item := range in.Items {
		o := BulkTargetOutcome{Item: item}
		o.Target, o.Err = s.CreateTarget(ctx, bulkItemInput(in, item, origin))
		if o.Err == nil && o.Target.IsActive() {
			added = append(added, o.Target)
		}
		if o.Err != nil && !isItemRefusal(o.Err) {
			// The pattern is the caller's text: not logged (the error is
			// sanitized); the item's result carries it back to the caller.
			s.logger.Warn("bulk scope entry failed", "error", logger.SanitizeError(o.Err))
		}
		out = append(out, o)
	}
	if len(added) > 0 && !in.Actor.system() {
		s.NotifyAdmins(ctx, tenantID, bulkTitle(len(added)), bulkBody(added))
	}
	return out, nil
}

// bulkItemInput is the single-entry input one item of a bulk add stands for.
func bulkItemInput(in BulkTargetsInput, item BulkTargetItem, origin scopedom.Origin) CreateTargetInput {
	return CreateTargetInput{
		TenantID:      in.TenantID,
		TargetType:    strings.TrimSpace(item.TargetType),
		Pattern:       strings.TrimSpace(item.Pattern),
		CreatedBy:     in.CreatedBy,
		Reason:        in.Reason,
		ExpiresInDays: in.ExpiresInDays,
		MaxTier:       in.MaxTier,
		Actor:         in.Actor,
		Origin:        origin,
		batch:         true,
	}
}

// isItemRefusal reports whether err is an answer about the item (a coded
// refusal, a duplicate, a validation error) rather than a failure.
func isItemRefusal(err error) bool {
	var dup *scopedom.DuplicateError
	var de *shared.DomainError
	return errors.As(err, &dup) || (errors.As(err, &de) && de.Code != "") || errors.Is(err, shared.ErrValidation)
}

func bulkTitle(n int) string {
	if n == 1 {
		return "Scope entry added"
	}
	return fmt.Sprintf("%d scope entries added", n)
}

// bulkBody names up to ten of the entries a batch added.
func bulkBody(ts []*scopedom.Target) string {
	const shown = 10
	parts := make([]string, 0, min(len(ts), shown))
	for i, t := range ts {
		if i == shown {
			break
		}
		parts = append(parts, fmt.Sprintf("%s %s", t.TargetType(), t.Pattern()))
	}
	body := strings.Join(parts, ", ")
	if len(ts) > shown {
		body += fmt.Sprintf(" and %d more", len(ts)-shown)
	}
	return body + " (permanent, added together)"
}
