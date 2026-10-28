package scope

// Marking many inventory assets out of scope in one request (research/124,
// RFC-054 §15.8): exact names or a rule (a parent domain wildcard, an
// address range) become scope exclusions. Each item is an ordinary
// CreateExclusion (pattern validation, duplicates, the Strict approval rule,
// the signer ledger), so a batch never does more than the same exclusions
// added one by one. An exclusion only narrows what may be scanned; taking
// one away again (the undo) is the existing bulk delete, which needs a
// recent re-authentication because it widens scope.
//
// The preview counts, for each pattern, the caller's visible inventory
// assets it would match (Layer 2 data scope; a restricted caller never
// learns about assets outside it) and changes nothing.

import (
	"context"
	"fmt"
	"time"

	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// MaxBulkExclusions bounds one bulk request (as a bulk add).
const MaxBulkExclusions = MaxBulkTargets

// bulkExclusionTypes are the exclusion kinds that describe inventory
// assets; path, finding_type and scanner exclusions need their own fields.
var bulkExclusionTypes = map[scopedom.ExclusionType]bool{
	scopedom.ExclusionTypeDomain: true, scopedom.ExclusionTypeSubdomain: true,
	scopedom.ExclusionTypeIPAddress: true, scopedom.ExclusionTypeIPRange: true,
	scopedom.ExclusionTypeCIDR: true, scopedom.ExclusionTypeURL: true,
	scopedom.ExclusionTypeRepository: true,
}

// BulkExclusionItem is one exclusion of a bulk request.
type BulkExclusionItem struct {
	ExclusionType string
	Pattern       string
}

// BulkExclusionsInput is a bulk request: the items and what they share.
type BulkExclusionsInput struct {
	TenantID  string
	Items     []BulkExclusionItem
	Reason    string
	CreatedBy string
	// Kind is why the items are out of scope (empty: do_not_scan) and
	// ExpiresAt their end date (nil: until re-included).
	Kind      string
	ExpiresAt *time.Time
}

// BulkExclusionOutcome is what happened to one item: Exclusion is the one it
// created, or Err why not (a *scopedom.DuplicateError names the existing
// exclusion).
type BulkExclusionOutcome struct {
	Item      BulkExclusionItem
	Exclusion *scopedom.Exclusion
	Err       error
}

// Bounds of a bulk exclusion request.
var (
	ErrBulkExclusionsEmpty   = shared.NewDomainError("BULK_EMPTY", "Add at least one exclusion", shared.ErrValidation)
	ErrBulkExclusionsTooMany = shared.NewDomainError("BULK_TOO_MANY", fmt.Sprintf("Add at most %d exclusions at once", MaxBulkExclusions), shared.ErrValidation)
	ErrBulkExclusionType     = shared.NewDomainError("EXCLUSION_TYPE_NOT_BULK", "Only domain, subdomain, address, range, CIDR, URL and repository exclusions can be added in bulk", shared.ErrValidation)
)

// bulkDefaultReason is recorded when the request gives none.
const bulkDefaultReason = "Marked out of scope from the inventory"

func checkBulkExclusions(tenantID string, items []BulkExclusionItem) (shared.ID, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return shared.ID{}, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	switch {
	case len(items) == 0:
		return shared.ID{}, ErrBulkExclusionsEmpty
	case len(items) > MaxBulkExclusions:
		return shared.ID{}, ErrBulkExclusionsTooMany
	}
	return tid, nil
}

// itemType parses an item's kind and keeps it to the bulk kinds.
func itemType(it BulkExclusionItem) (scopedom.ExclusionType, error) {
	t, err := scopedom.ParseExclusionType(it.ExclusionType)
	if err != nil {
		return "", err
	}
	if !bulkExclusionTypes[t] {
		return "", ErrBulkExclusionType
	}
	return t, nil
}

// CreateExclusions adds each item as a scope exclusion. A request-level
// error (bad tenant, no or too many items) writes nothing; otherwise every
// item has an outcome, in order. A repeated item is answered as a duplicate
// of the first.
func (s *Service) CreateExclusions(ctx context.Context, in BulkExclusionsInput) ([]BulkExclusionOutcome, error) {
	if _, err := checkBulkExclusions(in.TenantID, in.Items); err != nil {
		return nil, err
	}
	reason := in.Reason
	if reason == "" {
		reason = bulkDefaultReason
	}
	out := make([]BulkExclusionOutcome, 0, len(in.Items))
	for _, it := range in.Items {
		o := BulkExclusionOutcome{Item: it}
		if _, err := itemType(it); err != nil {
			o.Err = err
			out = append(out, o)
			continue
		}
		o.Exclusion, o.Err = s.CreateExclusion(ctx, CreateExclusionInput{
			TenantID: in.TenantID, ExclusionType: it.ExclusionType, Pattern: it.Pattern,
			Reason: reason, CreatedBy: in.CreatedBy, Origin: scopedom.OriginImport,
			Kind: in.Kind, ExpiresAt: in.ExpiresAt,
		})
		out = append(out, o)
	}
	return out, nil
}

// ExclusionMatch is how many of the caller's visible inventory assets a
// pattern matches, with up to ten of their names.
type ExclusionMatch struct {
	Matched int
	// OpenFindings is how many open findings those assets have: what a
	// permanent not_ours or retired exclusion would close.
	OpenFindings int
	Sample       []string
}

// ExclusionMatchCounter counts the matches of patterns in the database
// (*postgres.ScopeCoverageRepository), within a data scope (nil: the whole
// tenant).
type ExclusionMatchCounter interface {
	ExclusionMatches(ctx context.Context, tenantID shared.ID, ds *shared.DataScope, items []BulkExclusionItem) ([]ExclusionMatch, error)
}

// SetExclusionMatches wires the bulk exclusion preview.
func (s *Service) SetExclusionMatches(c ExclusionMatchCounter) { s.exclusionMatches = c }

// ExclusionPreview is the preview of one item: what it would match, or why
// it would be refused (Err).
type ExclusionPreview struct {
	Item  BulkExclusionItem
	Match ExclusionMatch
	Err   error
}

// PreviewExclusions answers, per item, how many of the caller's visible
// inventory assets the exclusion would match, and refuses the items a bulk
// add would refuse for their kind or pattern. Nothing is written. Without
// the data scope resolver the preview is refused (fail closed).
func (s *Service) PreviewExclusions(ctx context.Context, tenantID string, items []BulkExclusionItem) ([]ExclusionPreview, error) {
	tid, err := checkBulkExclusions(tenantID, items)
	if err != nil {
		return nil, err
	}
	if s.exclusionMatches == nil || s.dataScope == nil {
		return nil, fmt.Errorf("exclusion preview is not configured")
	}
	ds, err := s.dataScope.Resolve(ctx, tid)
	if err != nil {
		return nil, fmt.Errorf("resolve data scope: %w", err)
	}
	out := make([]ExclusionPreview, len(items))
	valid := make([]BulkExclusionItem, 0, len(items))
	at := make([]int, 0, len(items))
	for i, it := range items {
		out[i].Item = it
		t, err := itemType(it)
		if err == nil {
			_, err = scopedom.NewExclusion(tid, t, it.Pattern, bulkDefaultReason, nil, "")
		}
		if err != nil {
			out[i].Err = err
			continue
		}
		valid = append(valid, BulkExclusionItem{ExclusionType: string(t), Pattern: it.Pattern})
		at = append(at, i)
	}
	if len(valid) == 0 {
		return out, nil
	}
	matches, err := s.exclusionMatches.ExclusionMatches(ctx, tid, ds, valid)
	if err != nil {
		return nil, err
	}
	for k, i := range at {
		if k < len(matches) {
			out[i].Match = matches[k]
		}
	}
	return out, nil
}
