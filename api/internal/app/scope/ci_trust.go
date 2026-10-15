package scope

// Repository entries managed by CI trust configurations
// (docs/rfcs/RFC-054-scope-model.md, "Repository entries and CI trusts").
//
// A trust claims repository patterns (cirun.ScopePatterns). Sync keeps one
// scope entry per pattern linked to the trust: an equal entry that already
// exists is linked, never duplicated; otherwise an entry with origin
// ci_trust is created as the person who saved the trust, through
// CreateTarget's own decision (their step-up and approval rights, the
// organization's approval mode), so it is in effect at once only where a
// person adding it by hand would get that too. Only a caller who may change
// scope creates entries (MayCreate). Patterns the trust no longer claims are
// unlinked, and a ci_trust entry with no link left is retired. An entry a
// person deleted is never created again for the same link
// (TargetRemovedAt). A verified pipeline run under a pattern is recorded on
// its link as evidence and may link an existing equal entry, never create
// one; with the organization's opt-in "ci_scope_requires_proof", new entries
// wait inactive for that run.
//
// Every write goes through CreateTarget or the same ledger commit as a
// person's change, and every read is tenant-scoped.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// ErrCITrustLinksNotWired: the link store is not configured.
var ErrCITrustLinksNotWired = errors.New("ci trust scope links are not wired")

// SetCITrustLinks wires the store of CI trust links. Without it trusts manage
// no scope and no entry counts as managed.
func (s *Service) SetCITrustLinks(r scopedom.CITrustLinkRepository) { s.ciTrustLinks = r }

// CITrustScope is a trust's wanted scope: its patterns (empty retires every
// entry it manages) and who changed the trust.
type CITrustScope struct {
	TrustID   shared.ID
	TrustName string
	Patterns  []string
	// By is the user who created or changed the trust ("" for the platform).
	By string
	// Actor is that user and whether they may approve scope entries; new
	// entries go through CreateTarget's decision as them.
	Actor Actor
	// MayCreate: the user may change scope (attack_surface:scope:write), so
	// missing entries are created; otherwise only existing equal entries
	// are linked.
	MayCreate bool
}

// SyncCITrust brings the trust's managed entries in line with its patterns
// and answers what it did per pattern. A pattern the platform refuses (a
// guardrail) is reported, not fatal.
func (s *Service) SyncCITrust(ctx context.Context, tenantID shared.ID, in CITrustScope) ([]scopedom.CITrustSyncOutcome, error) {
	if s.ciTrustLinks == nil {
		return nil, ErrCITrustLinksNotWired
	}
	if tenantID.IsZero() || in.TrustID.IsZero() {
		return nil, fmt.Errorf("%w: tenant and trust are required", shared.ErrValidation)
	}
	links, err := s.ciTrustLinks.ListByTrust(ctx, tenantID, in.TrustID)
	if err != nil {
		return nil, err
	}
	want := make([]string, 0, len(in.Patterns))
	wanted := map[string]bool{}
	for _, p := range in.Patterns {
		if p = scopedom.NormalizeRepositoryPattern(p); p != "" && !wanted[p] {
			wanted[p] = true
			want = append(want, p)
		}
	}
	out := make([]scopedom.CITrustSyncOutcome, 0, len(want)+len(links))
	have := map[string]scopedom.CITrustLink{}
	for _, l := range links {
		if wanted[l.Pattern] {
			have[l.Pattern] = l
			continue
		}
		if err := s.ciTrustLinks.Delete(ctx, tenantID, in.TrustID, l.Pattern); err != nil {
			return out, err
		}
		if err := s.retireCITrustEntry(ctx, tenantID, l.TargetID); err != nil {
			return out, err
		}
		out = append(out, scopedom.CITrustSyncOutcome{Pattern: l.Pattern, Action: scopedom.CITrustRetired, TargetID: l.TargetID})
	}
	var requiresProof *bool
	for _, p := range want {
		if l, ok := have[p]; ok {
			action := scopedom.CITrustKept
			if l.TargetID == nil {
				action = scopedom.CITrustRemoved // a person deleted it: not again
			}
			out = append(out, scopedom.CITrustSyncOutcome{Pattern: p, Action: action, TargetID: l.TargetID})
			continue
		}
		if requiresProof == nil {
			v, err := s.ciScopeRequiresProof(ctx, tenantID)
			if err != nil {
				return out, err
			}
			requiresProof = &v
		}
		o, err := s.ensureCITrustEntry(ctx, tenantID, in, p, *requiresProof)
		if err != nil {
			return out, err
		}
		out = append(out, o)
	}
	s.notifyCITrustAdded(ctx, tenantID, in, out)
	return out, nil
}

// notifyCITrustAdded tells the administrators which entries a trust added,
// as any widening by a person is told.
func (s *Service) notifyCITrustAdded(ctx context.Context, tenantID shared.ID, in CITrustScope, out []scopedom.CITrustSyncOutcome) {
	if in.Actor.system() {
		return
	}
	var added []string
	for _, o := range out {
		if o.Action == scopedom.CITrustCreated {
			added = append(added, o.Pattern)
		}
	}
	if len(added) == 0 {
		return
	}
	s.NotifyAdmins(ctx, tenantID, "Repositories added to scope by a CI trust",
		fmt.Sprintf("The CI trust %q added %s to scope.", in.TrustName, strings.Join(added, ", ")))
}

// ensureCITrustEntry links the tenant's entry with this pattern to the trust,
// creating it when there is none.
func (s *Service) ensureCITrustEntry(ctx context.Context, tenantID shared.ID, in CITrustScope, pattern string, inactive bool) (scopedom.CITrustSyncOutcome, error) {
	o := scopedom.CITrustSyncOutcome{Pattern: pattern}
	link := func(id shared.ID, action string) (scopedom.CITrustSyncOutcome, error) {
		if err := s.ciTrustLinks.Put(ctx, tenantID, in.TrustID, pattern, id); err != nil {
			return o, err
		}
		o.Action, o.TargetID = action, &id
		return o, nil
	}
	existing, err := s.targetRepo.FindByPattern(ctx, tenantID, scopedom.TargetTypeRepository, pattern)
	if err != nil {
		return o, fmt.Errorf("find scope entry: %w", err)
	}
	if existing != nil {
		return link(existing.ID, scopedom.CITrustLinked)
	}
	if !in.MayCreate || in.Actor.system() {
		o.Action, o.Err = scopedom.CITrustRefused, scopedom.ErrCITrustNoScopeWrite
		return o, nil
	}
	t, err := s.CreateTarget(ctx, CreateTargetInput{
		TenantID:    tenantID.String(),
		TargetType:  string(scopedom.TargetTypeRepository),
		Pattern:     pattern,
		Description: fmt.Sprintf("Managed by the CI trust %q", in.TrustName),
		CreatedBy:   in.By,
		Origin:      scopedom.OriginCITrust,
		Actor:       in.Actor,
		batch:       true,
		inactive:    inactive,
	})
	var dup *scopedom.DuplicateError
	switch {
	case errors.As(err, &dup):
		return link(dup.Existing.ID, scopedom.CITrustLinked) // created meanwhile
	case err != nil && isItemRefusal(err):
		o.Action, o.Err = scopedom.CITrustRefused, err
		return o, nil
	case err != nil:
		return o, err
	}
	return link(t.ID(), scopedom.CITrustCreated)
}

// retireCITrustEntry deletes an entry a trust created once no trust links
// it. An entry a person created stays as it is.
func (s *Service) retireCITrustEntry(ctx context.Context, tenantID shared.ID, targetID *shared.ID) error {
	if targetID == nil {
		return nil
	}
	t, err := s.targetRepo.GetByID(ctx, tenantID, *targetID)
	if errors.Is(err, shared.ErrNotFound) || errors.Is(err, scopedom.ErrTargetNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if t.Origin() != scopedom.OriginCITrust {
		return nil
	}
	n, err := s.ciTrustLinks.CountForTarget(ctx, tenantID, *targetID)
	if err != nil || n > 0 {
		return err
	}
	if err := s.commitEntry(ctx, ledgerEntryOf(t, time.Now()), t, true, func() error {
		return s.targetRepo.Delete(ctx, tenantID, *targetID)
	}); err != nil {
		return fmt.Errorf("retire scope entry: %w", err)
	}
	s.logger.Info("scope entry retired with its ci trust", "id", targetID.String())
	return nil
}

// CITrustSeen records a verified pipeline run under the trust: the evidence
// on each link whose pattern covers the repository and has none yet, and an
// entry waiting for proof is put into effect. A pattern with no link yet is
// linked to an equal entry when one exists; nothing is ever created here (a
// run is not a person, and an entry a person deleted stays deleted).
func (s *Service) CITrustSeen(ctx context.Context, tenantID shared.ID, in CITrustScope, ev scopedom.CITrustEvidence) error {
	if s.ciTrustLinks == nil || len(in.Patterns) == 0 {
		return nil
	}
	links, err := s.ciTrustLinks.ListByTrust(ctx, tenantID, in.TrustID)
	if err != nil {
		return err
	}
	if !linksCover(links, in.Patterns) {
		in.Actor, in.MayCreate = Actor{}, false // link existing entries only
		if _, err := s.SyncCITrust(ctx, tenantID, in); err != nil {
			return err
		}
		if links, err = s.ciTrustLinks.ListByTrust(ctx, tenantID, in.TrustID); err != nil {
			return err
		}
	}
	if ev.At.IsZero() {
		ev.At = time.Now().UTC()
	}
	for _, l := range links {
		if l.SeenAt != nil || !scopedom.MatchesPattern(scopedom.TargetTypeRepository, l.Pattern, ev.Repository) {
			continue
		}
		marked, err := s.ciTrustLinks.MarkSeen(ctx, tenantID, in.TrustID, l.Pattern, ev)
		if err != nil {
			return err
		}
		if marked && l.TargetID != nil {
			if err := s.activateProvenEntry(ctx, tenantID, *l.TargetID); err != nil {
				return err
			}
		}
	}
	return nil
}

func linksCover(links []scopedom.CITrustLink, patterns []string) bool {
	have := map[string]bool{}
	for _, l := range links {
		have[l.Pattern] = true
	}
	for _, p := range patterns {
		if !have[scopedom.NormalizeRepositoryPattern(p)] {
			return false
		}
	}
	return true
}

// activateProvenEntry puts into effect a trust's entry that waited for its
// first verified run.
func (s *Service) activateProvenEntry(ctx context.Context, tenantID, targetID shared.ID) error {
	t, err := s.targetRepo.GetByID(ctx, tenantID, targetID)
	if err != nil {
		return err
	}
	if t.Origin() != scopedom.OriginCITrust || t.Status() != scopedom.StatusInactive {
		return nil
	}
	now := time.Now().UTC()
	before := ledgerEntryOf(t, now)
	if err := s.widenEntry(ctx, t, Actor{}, now); err != nil {
		return err
	}
	if err := s.commitEntry(ctx, before, t, false, func() error { return s.targetRepo.Update(ctx, t) }); err != nil {
		return fmt.Errorf("activate proven scope entry: %w", err)
	}
	s.scheduleJoin(tenantID)
	s.logger.Info("scope entry proven by a verified ci run", "id", targetID.String())
	return nil
}

// ciScopeRequiresProof reads the organization's opt-in setting (off when
// no settings are wired).
func (s *Service) ciScopeRequiresProof(ctx context.Context, tenantID shared.ID) (bool, error) {
	if s.settings == nil {
		return false, nil
	}
	st, err := s.settings.GetScopeSettings(ctx, tenantID.String())
	if err != nil {
		return false, fmt.Errorf("read scope settings: %w", err)
	}
	return st != nil && st.CIScopeRequiresProof, nil
}

// ciTrustManaged reports whether a trust still manages the entry: a
// ci_trust entry with at least one link.
func (s *Service) ciTrustManaged(ctx context.Context, t *scopedom.Target) (bool, error) {
	if s.ciTrustLinks == nil || t.Origin() != scopedom.OriginCITrust {
		return false, nil
	}
	n, err := s.ciTrustLinks.CountForTarget(ctx, t.TenantID(), t.ID())
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// refuseCITrustManaged answers ErrCITrustManaged for an entry a trust
// manages.
func (s *Service) refuseCITrustManaged(ctx context.Context, t *scopedom.Target) error {
	managed, err := s.ciTrustManaged(ctx, t)
	if err != nil {
		return err
	}
	if managed {
		return scopedom.ErrCITrustManaged
	}
	return nil
}

// CITrustLinksFor lists the trust links of these entries, by entry id.
func (s *Service) CITrustLinksFor(ctx context.Context, tenantID shared.ID, ids []shared.ID) (map[string][]scopedom.CITrustLink, error) {
	out := map[string][]scopedom.CITrustLink{}
	if s.ciTrustLinks == nil || len(ids) == 0 {
		return out, nil
	}
	links, err := s.ciTrustLinks.ListByTargets(ctx, tenantID, ids)
	if err != nil {
		return nil, err
	}
	for _, l := range links {
		if l.TargetID != nil && l.TenantID.Equals(tenantID) {
			out[l.TargetID.String()] = append(out[l.TargetID.String()], l)
		}
	}
	return out, nil
}

// CITrustLinks lists one trust's links (patterns, entries, evidence).
func (s *Service) CITrustLinks(ctx context.Context, tenantID, trustID shared.ID) ([]scopedom.CITrustLink, error) {
	if s.ciTrustLinks == nil {
		return nil, nil
	}
	links, err := s.ciTrustLinks.ListByTrust(ctx, tenantID, trustID)
	if err != nil {
		s.logger.Warn("ci trust scope links not read", "error", logger.SanitizeError(err))
		return nil, err
	}
	return links, nil
}
