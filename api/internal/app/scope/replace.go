package scope

// Replacing a scope entry's pattern (docs/architecture/scope-entry-replace.md).
//
// The pattern of an entry is never edited in place: its approvals, audit
// history and the scans that name it are bound to it. ReplaceTarget creates
// a new entry of the same type with the new pattern instead, through every
// check and approval rule a new entry goes through (CreateTarget), and links
// it to the old one:
//
//   - the replacement in effect at once: the old entry is retired
//     (superseded) in the same transaction, and the job signer's ledger puts
//     the new entry before the old one is taken out;
//   - the replacement waiting for approval: the old entry stays in effect
//     until the replacement is approved (commitEntryUpdate retires it then,
//     in the transaction that puts the replacement into effect). Rejected or
//     deleted, the replacement leaves the old entry as it was.
//
// A narrowing or an equal-size correction follows the same rule as adding
// an entry, never a weaker one.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/scanzone"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/scope/ipset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/jobsign"
)

// replacementStore saves a replacement in one transaction
// (*postgres.ScopeTargetRepository).
type replacementStore interface {
	SaveReplacement(ctx context.Context, created *scopedom.Target, updated ...*scopedom.Target) error
	PendingReplacement(ctx context.Context, tenantID, id shared.ID) (*shared.ID, error)
}

// ZoneLister lists a tenant's scan zones (*postgres.ScanZoneRepository).
type ZoneLister interface {
	List(ctx context.Context, tenantID shared.ID) ([]*scanzone.Zone, error)
}

// SetZones wires the scan zones a replacement reports on. Without it the
// zone note is empty.
func (s *Service) SetZones(z ZoneLister) { s.zones = z }

// ErrReplaceUnavailable: the target store cannot save a replacement
// atomically; nothing is changed (fail closed).
var ErrReplaceUnavailable = shared.NewDomainError("REPLACE_UNAVAILABLE",
	"replacing a scope entry's pattern is not available", shared.ErrConflict)

// ReplaceTargetInput replaces the pattern of entry TargetID.
type ReplaceTargetInput struct {
	TenantID string
	TargetID string
	Pattern  string
	Reason   string
	Actor    Actor
}

// ZoneUse is a scan zone that names the old entry's addresses in its own
// ranges.
type ZoneUse struct {
	ID   string
	Name string
	// Ranges are the zone's ranges now; Suggested are its ranges with the
	// old entry's addresses swapped for the new entry's (empty when that
	// does not fit a zone). The zone changes only through the scan zone API
	// (sensors:zones:write), never here.
	Ranges    []string
	Suggested []string
}

// ReplaceResult is a replacement, done or previewed.
type ReplaceResult struct {
	Old *scopedom.Target
	// New is the replacement (not saved in a preview).
	New *scopedom.Target
	// OldRetired: the old entry is superseded now; false while the
	// replacement waits for approval (the old entry stays in effect).
	OldRetired     bool
	StepUpRequired bool
	Change         scopedom.CoverageChange
	Zones          []ZoneUse
}

// PreviewReplaceTarget runs ReplaceTarget's checks and answers what it would
// do, without saving or asking for step-up. An error is the refusal
// ReplaceTarget would give.
func (s *Service) PreviewReplaceTarget(ctx context.Context, in ReplaceTargetInput) (*ReplaceResult, error) {
	return s.replaceTarget(ctx, in, true)
}

// ReplaceTarget replaces the pattern of an entry in effect (see the file
// comment). The route requires scope:write; step-up and approvals are those
// of a new entry.
func (s *Service) ReplaceTarget(ctx context.Context, in ReplaceTargetInput) (*ReplaceResult, error) {
	return s.replaceTarget(ctx, in, false)
}

// replaceableEntry reads the entry to replace (tenant-scoped: another
// tenant's entry is not found) and refuses one that cannot be replaced.
func (s *Service) replaceableEntry(ctx context.Context, store replacementStore, in ReplaceTargetInput, now time.Time) (*scopedom.Target, error) {
	tenantID, err := shared.IDFromString(in.TenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	id, err := shared.IDFromString(in.TargetID)
	if err != nil {
		return nil, shared.ErrNotFound
	}
	old, err := s.targetRepo.GetByID(ctx, tenantID, id)
	if err != nil {
		return nil, err
	}
	switch {
	case old.IsSuperseded():
		return nil, scopedom.ErrEntrySuperseded
	case old.IsProgramEntry():
		return nil, scopedom.ErrProgramManaged
	case !old.InEffect(now):
		return nil, scopedom.ErrEntryNotReplaceable
	}
	if err := s.refuseCITrustManaged(ctx, old); err != nil {
		return nil, err
	}
	if pending, err := store.PendingReplacement(ctx, tenantID, id); err != nil {
		return nil, err
	} else if pending != nil {
		return nil, scopedom.ErrReplacementPending
	}
	return old, nil
}

func (s *Service) replaceTarget(ctx context.Context, in ReplaceTargetInput, preview bool) (*ReplaceResult, error) {
	store, ok := s.targetRepo.(replacementStore)
	if !ok {
		return nil, ErrReplaceUnavailable
	}
	now := time.Now().UTC()
	old, err := s.replaceableEntry(ctx, store, in, now)
	if err != nil {
		return nil, err
	}
	tenantID, targetType := old.TenantID(), old.TargetType()
	reason := strings.TrimSpace(in.Reason)
	if reason == "" {
		return nil, scopedom.ErrReplaceReasonRequired
	}
	pattern := strings.TrimSpace(in.Pattern)
	if targetType == scopedom.TargetTypeRepository {
		pattern = scopedom.NormalizeRepositoryPattern(pattern)
	}
	if strings.EqualFold(pattern, old.Pattern()) {
		return nil, scopedom.ErrReplaceSamePattern
	}
	next, d, err := s.newReplacement(ctx, old, pattern, reason, in.Actor, now, preview)
	if err != nil {
		return nil, err
	}
	res := &ReplaceResult{
		Old: old, New: next, StepUpRequired: !d.request && !in.Actor.system(),
		Change: scopedom.ReplacementChange(targetType, old.Pattern(), pattern),
	}
	if res.Zones, err = s.zonesUsing(ctx, tenantID, targetType, old.Pattern(), pattern); err != nil {
		return nil, err
	}
	if preview {
		res.OldRetired = next.InEffect(now)
		return res, nil
	}

	if err := s.commitReplacement(ctx, store, next, old, now); err != nil {
		if errors.Is(err, scopedom.ErrTargetAlreadyExists) {
			if dup := s.targetDuplicate(ctx, tenantID, targetType, pattern); dup != nil {
				return nil, dup
			}
		}
		return nil, err
	}
	res.OldRetired = old.IsSuperseded()
	if next.IsPending() {
		s.notifyRequested(ctx, next)
	} else if !in.Actor.system() {
		s.NotifyAdmins(ctx, tenantID, "Scope entry pattern replaced",
			fmt.Sprintf("%s %s replaced %s (%s). Reason: %s", targetType, pattern, old.Pattern(), res.Change, reason))
	}
	if next.IsActive() {
		s.scheduleJoin(tenantID)
	}
	s.logger.Info("scope target replaced", "old_id", old.ID().String(), "new_id", next.ID().String(),
		"status", next.Status().String(), "old_retired", res.OldRetired)
	return res, nil
}

// newReplacement builds the replacement entry through every check of a new
// entry: the pattern, the platform guardrails (public suffixes, the deny
// list, CIDR caps), duplicates, then the one-off, request, tier and approval
// rules with step-up (decideNewEntry; no step-up in a preview).
func (s *Service) newReplacement(ctx context.Context, old *scopedom.Target, pattern, reason string, actor Actor,
	now time.Time, preview bool,
) (*scopedom.Target, entryDecision, error) {
	tenantID, targetType := old.TenantID(), old.TargetType()
	if err := scopedom.ValidatePattern(targetType, pattern); err != nil {
		return nil, entryDecision{}, err
	}
	g := scopedom.DefaultGuardrails()
	if s.guardrails != nil {
		g = *s.guardrails
	}
	if err := g.CheckPattern(targetType, pattern); err != nil {
		return nil, entryDecision{}, err
	}
	if err := s.targetDuplicate(ctx, tenantID, targetType, pattern); err != nil {
		return nil, entryDecision{}, err
	}
	create := CreateTargetInput{
		TenantID: tenantID.String(), TargetType: targetType.String(), Pattern: pattern, Reason: reason,
		ExpiresAt: old.ExpiresAt(), MaxTier: old.MaxTier().String(), Actor: actor,
	}
	d, err := s.decideNewEntry(ctx, tenantID, targetType, create, now, preview)
	if err != nil {
		return nil, d, err
	}
	next, err := scopedom.NewEntry(tenantID, targetType, pattern, old.Description(), actor.UserID, scopedom.EntryOptions{
		Reason: reason, ExpiresAt: d.expiresAt, MaxTier: d.tier, ApprovalsRequired: d.approvals,
		IntrusivePermanent: d.intrusivePermanent, Now: now,
	})
	if err != nil {
		return nil, d, err
	}
	if err := copyEntrySettings(old, next); err != nil {
		return nil, d, err
	}
	next.SetOrigin(entryOrigin("", actor, d.request))
	next.SetSupersedes(old.ID())
	return next, d, nil
}

// copyEntrySettings carries what the old entry was set up with onto its
// replacement: priority, tags, discovery, the port and protocol limit and
// the authorization source. Tier and expiry go through the new-entry rules
// (decideNewEntry).
func copyEntrySettings(old, next *scopedom.Target) error {
	if old.Priority() > 0 {
		if err := next.UpdatePriority(old.Priority()); err != nil {
			return err
		}
	}
	if len(old.Tags()) > 0 {
		next.UpdateTags(append([]string(nil), old.Tags()...))
	}
	next.SetDiscovery(old.DiscoverySetting())
	if err := next.SetConstraint(old.Constraint()); err != nil {
		return err
	}
	var ref *shared.ID
	if old.AuthorizationSource() == scopedom.AuthLetter {
		ref = old.LetterID()
	}
	if src := old.AuthorizationSource(); src != "" {
		if err := next.SetAuthorization(src, ref); err != nil {
			return err
		}
	}
	return nil
}

// commitReplacement saves a new replacement. In effect at once, it retires
// old in the same transaction; pending, old is not touched.
func (s *Service) commitReplacement(ctx context.Context, store replacementStore, next, old *scopedom.Target, now time.Time) error {
	if !next.InEffect(now) {
		return s.commitEntry(ctx, nil, next, false, func() error {
			if err := store.SaveReplacement(ctx, next); err != nil {
				return fmt.Errorf("failed to save scope replacement: %w", err)
			}
			return nil
		})
	}
	oldBefore := ledgerEntryOf(old, now)
	old.Supersede(next.ID(), now)
	return s.retireWith(ctx, nil, next, oldBefore, old, func() error {
		if err := store.SaveReplacement(ctx, next, old); err != nil {
			return fmt.Errorf("failed to save scope replacement: %w", err)
		}
		return nil
	})
}

// retireWith orders the ledger for a replacement taking effect: the signer
// accepts the new entry (a widening, before anything is saved), save writes
// both entries in one transaction, and the old entry's removal (a
// narrowing) goes to the signer after.
func (s *Service) retireWith(ctx context.Context, before *jobsign.LedgerEntry, next *scopedom.Target,
	oldBefore *jobsign.LedgerEntry, old *scopedom.Target, save func() error,
) error {
	return s.commitEntry(ctx, before, next, false, func() error {
		return s.commitEntry(ctx, oldBefore, old, false, save)
	})
}

// commitEntryUpdate saves a change to an existing entry t (an approval, an
// activation) through the ledger hook. When the change puts a replacement
// into effect, the entry it replaces is retired in the same transaction.
func (s *Service) commitEntryUpdate(ctx context.Context, before *jobsign.LedgerEntry, t *scopedom.Target) error {
	now := time.Now().UTC()
	old, err := s.replacedEntry(ctx, t, now)
	if err != nil {
		return err
	}
	if old == nil {
		return s.commitEntry(ctx, before, t, false, func() error {
			if err := s.targetRepo.Update(ctx, t); err != nil {
				return fmt.Errorf("failed to update scope target: %w", err)
			}
			return nil
		})
	}
	store, ok := s.targetRepo.(replacementStore)
	if !ok {
		return ErrReplaceUnavailable
	}
	oldBefore := ledgerEntryOf(old, now)
	old.Supersede(t.ID(), now)
	if err := s.retireWith(ctx, before, t, oldBefore, old, func() error {
		if err := store.SaveReplacement(ctx, nil, t, old); err != nil {
			return fmt.Errorf("failed to save scope replacement: %w", err)
		}
		return nil
	}); err != nil {
		return err
	}
	s.logger.Info("scope target retired by its replacement", "old_id", old.ID().String(), "new_id", t.ID().String())
	return nil
}

// replacedEntry is the entry t replaces when t is in effect and that entry
// still exists and is not superseded yet; nil otherwise.
func (s *Service) replacedEntry(ctx context.Context, t *scopedom.Target, now time.Time) (*scopedom.Target, error) {
	if t.Supersedes() == nil || !t.InEffect(now) {
		return nil, nil
	}
	old, err := s.targetRepo.GetByID(ctx, t.TenantID(), *t.Supersedes())
	if errors.Is(err, scopedom.ErrTargetNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if old.IsSuperseded() {
		return nil, nil
	}
	return old, nil
}

// zonesUsing lists the tenant's scan zones that name the old pattern's
// addresses in their own ranges (address types only: a zone range that lies
// inside the old pattern), with the ranges the zone would have with those
// ranges swapped for the new pattern's addresses. A zone whose wider range
// merely contains the old pattern is not listed: it needs no change.
func (s *Service) zonesUsing(ctx context.Context, tenantID shared.ID, t scopedom.TargetType, oldPattern, newPattern string) ([]ZoneUse, error) {
	if s.zones == nil || !scopedom.IsAddressType(t) {
		return nil, nil
	}
	oldSet, okO := scopedom.AddressSet(oldPattern)
	newSet, okN := scopedom.AddressSet(newPattern)
	if !okO || !okN {
		return nil, nil
	}
	zones, err := s.zones.List(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list scan zones: %w", err)
	}
	var out []ZoneUse
	for _, z := range zones {
		if z == nil || z.TenantID != tenantID {
			continue
		}
		keep := make([]ipset.Range, 0, len(z.Ranges))
		used := false
		for _, p := range z.Ranges {
			r, ok := ipset.PrefixRange(p)
			if !ok {
				continue
			}
			if ipset.Of(r).Subtract(oldSet).Empty() {
				used = true // this zone range is (part of) the old pattern
				continue
			}
			keep = append(keep, r)
		}
		if !used {
			continue
		}
		use := ZoneUse{ID: z.ID.String(), Name: z.Name, Ranges: z.RangeStrings()}
		next := ipset.Of(append(keep, newSet.Ranges()...)...)
		if suggested, err := next.Prefixes(ipset.PieceBits{}, scanzone.MaxRangesPerZone); err == nil {
			for _, p := range suggested {
				use.Suggested = append(use.Suggested, p.String())
			}
		}
		out = append(out, use)
	}
	return out, nil
}
