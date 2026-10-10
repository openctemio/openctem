package bountyprogram

// Subscriptions to public programs (RFC-065 §16). Subscribing creates the
// organization's own program from a catalog program: its group (the
// subscriber joins), its program exclusions and its entries, all entries
// inactive (status pending_attestation): only passive work runs until a
// member accepts the terms with Resume (the same attestation and step-up as
// an import). A feed change applies like a sync, fail-safe: narrowing at
// once; anything that widens, or changed rules or terms, takes the entries
// out of effect again and asks for a new acceptance.

import (
	"context"
	"fmt"
	"strings"

	bp "github.com/openctemio/openctem/api/pkg/domain/bountyprogram"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// SetCatalog wires the public program catalog.
func (s *Service) SetCatalog(c bp.CatalogRepository) { s.catalog = c }

// Catalog lists the published programs (public data, any tenant).
func (s *Service) Catalog(ctx context.Context, search string, limit, offset int) ([]bp.PublicProgram, int, error) {
	if s.catalog == nil {
		return nil, 0, nil
	}
	return s.catalog.ListPublic(ctx, strings.TrimSpace(search), limit, offset)
}

// Subscribe creates the organization's program for a catalog program. The
// route requires attack_surface:programs:write; no entry is in effect
// until a member accepts the terms.
func (s *Service) Subscribe(ctx context.Context, tenantID, actor, publicID shared.ID) (*bp.Program, *Preview, error) {
	if actor.IsZero() {
		return nil, nil, fmt.Errorf("%w: a person subscribes to a program", shared.ErrForbidden)
	}
	if s.catalog == nil {
		return nil, nil, bp.ErrNotFound
	}
	pub, err := s.catalog.GetPublic(ctx, publicID)
	if err != nil {
		return nil, nil, err
	}
	if pub.RemovedAt != nil || !pub.Open {
		return nil, nil, bp.ErrPublicProgramGone
	}
	pv, err := s.previewItems(ctx, tenantID, pub.URL, pub.TermsText, pub.Rules, pub.Items, nil)
	if err != nil {
		return nil, nil, err
	}
	now := s.now()
	pid := pub.ID
	p := &bp.Program{
		ID: shared.NewID(), TenantID: tenantID, Name: clip(pub.Name, bp.MaxNameLength), Platform: clip(pub.Platform, bp.MaxPlatformLength),
		ProgramURL: pub.URL, Visibility: bp.VisibilityPublic, TermsText: pub.TermsText,
		Status: bp.StatusPendingAttestation, ScopeSource: bp.ScopeSourcePublicFeed,
		Rules: pv.rules, ScopeItems: pub.Items, TermsSHA256: pv.TermsSHA256, PublicProgramID: &pid,
		CreatedBy: &actor, CreatedAt: now, UpdatedAt: now,
	}
	entries, err := s.newEntries(p, pv, actor, false)
	if err != nil {
		return nil, nil, err
	}
	member := actor
	group := bp.NewGroup{ID: shared.NewID(), Name: clip("Program: "+p.Name, 100),
		Slug: "program-" + strings.ReplaceAll(p.ID.String(), "-", "")[:16], Member: &member}
	// Inactive entries authorize nothing: no ledger widening.
	if err := s.repo.Import(ctx, bp.ImportWrite{Program: p, Group: group, Entries: entries, Exclusions: s.exclusions(p, pv)}); err != nil {
		return nil, nil, err
	}
	s.ensureTargets(ctx, p, pv)
	s.assign(ctx, p)
	return p, pv, nil
}

// ApplyFeedChange brings one subscribed program up to date with its
// catalog program (the importer, after a feed run). It returns what it
// did: "", "narrowed", "needs_acceptance", "suspended".
func (s *Service) ApplyFeedChange(ctx context.Context, ref bp.ProgramRef) (string, error) {
	p, err := s.repo.GetByID(ctx, ref.TenantID, ref.ProgramID)
	if err != nil {
		return "", err
	}
	if p.PublicProgramID == nil || p.Status == bp.StatusEnded || s.catalog == nil {
		return "", nil
	}
	pub, err := s.catalog.GetPublic(ctx, *p.PublicProgramID)
	if err != nil {
		return "", err
	}
	if pub.RemovedAt != nil || !pub.Open {
		if p.Status == bp.StatusActive {
			if err := s.suspend(ctx, p, shared.ID{}, "the program is no longer published or takes no submissions"); err != nil {
				return "", err
			}
			return "suspended", nil
		}
		return "", nil
	}
	pv, err := s.previewItems(ctx, p.TenantID, pub.URL, pub.TermsText, pub.Rules, pub.Items, p)
	if err != nil {
		return "", err
	}
	if pv.TermsSHA256 == p.TermsSHA256 {
		return "", nil
	}
	diff := bp.DiffPlans(bp.PlanScope(p.ScopeItems), bp.PlanScope(pub.Items))
	rulesChanged := bp.NewTerms(pub.URL, pub.Rules, nil).WithText(pub.TermsText).SHA256() !=
		bp.NewTerms(p.ProgramURL, p.Rules, nil).WithText(p.TermsText).SHA256()
	if !diff.Widens() && !rulesChanged && p.Status != bp.StatusPendingAttestation {
		// Only narrowing: apply at once (saved with the program row), the
		// program stays in effect.
		p.ScopeItems, p.TermsSHA256, p.UpdatedAt = pub.Items, pv.TermsSHA256, s.now()
		if err := s.narrow(ctx, p, diff); err != nil {
			return "", err
		}
		s.audited(ctx, p, shared.ID{}, "Program scope narrowed by the program feed", map[string]any{
			"entries_removed": len(diff.RemovedEntries), "exclusions_added": len(diff.AddedExclusion)})
		return "narrowed", nil
	}
	if err := s.replaceAwaitingAcceptance(ctx, p, pub, pv); err != nil {
		return "", err
	}
	if s.notifier != nil {
		body := fmt.Sprintf("%s changed its scope or terms; a member must accept the new terms before its targets are scanned actively", p.Name)
		if n := len(diff.AddedEntries); n > 0 {
			body = fmt.Sprintf("%s lists %d new in-scope targets; a member must accept the new terms before they are scanned actively", p.Name, n)
		}
		s.notifier.NotifyAdmins(ctx, p.TenantID, "Program scope changed: accept the terms again", body)
	}
	return "needs_acceptance", nil
}

// replaceAwaitingAcceptance replaces a subscribed program's scope, rules and
// terms with the catalog's and takes every entry out of effect in one
// transaction: status pending_attestation until a member accepts.
func (s *Service) replaceAwaitingAcceptance(ctx context.Context, p *bp.Program, pub *bp.PublicProgram, pv *Preview) error {
	current, err := s.repo.Entries(ctx, p.TenantID, p.ID)
	if err != nil {
		return err
	}
	keep := map[string]bool{}
	for _, e := range pv.Entries {
		if e.Status == PlanKeep {
			keep[entryKey(e.TargetType, e.Pattern)] = true
		}
	}
	var drop []shared.ID
	stopped := make([]shared.ID, 0, len(current))
	for _, e := range current {
		stopped = append(stopped, e.ID())
		if !keep[entryKey(e.TargetType(), e.Pattern())] {
			drop = append(drop, e.ID())
		}
	}
	now := s.now()
	p.Status, p.Rules, p.ScopeItems, p.TermsText, p.TermsSHA256 = bp.StatusPendingAttestation, pv.rules, pub.Items, pub.TermsText, pv.TermsSHA256
	p.ProgramURL, p.Pending, p.UpdatedAt = pub.URL, nil, now
	create, err := s.newEntries(p, pv, shared.ID{}, false)
	if err != nil {
		return err
	}
	// Narrowing only (entries stop): the ledger hears of every entry that
	// leaves effect.
	if err := s.commit(ctx, p.TenantID, shared.ID{}, nil, stopped, func() error {
		return s.repo.ReplaceScope(ctx, bp.ScopeWrite{Program: p, CreateEntries: create, DeleteEntryIDs: drop,
			Exclusions: s.exclusions(p, pv), DeactivateEntries: true})
	}); err != nil {
		return err
	}
	s.audited(ctx, p, shared.ID{}, "Program terms changed by the program feed; entries wait for a new acceptance",
		map[string]any{"entries_created": len(create), "entries_removed": len(drop)})
	s.ensureTargets(ctx, p, pv)
	s.assign(ctx, p)
	return nil
}
