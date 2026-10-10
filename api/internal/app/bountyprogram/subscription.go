package bountyprogram

// Followed public programs (RFC-065 §16). Following creates the
// organization's own program from a catalog program: its group (the
// follower joins), its program exclusions and its entries, all entries
// inactive (status pending_attestation): only passive work runs until a
// member accepts the terms with Resume (the same attestation and step-up as
// an import). A feed target is never permission to test: entries are made
// only from targets the program itself published; targets the feed inferred
// are suggestions a member confirms first. A feed change is applied
// fail-safe: narrowing alone at once; anything that widens, or changed rules
// or terms, takes every entry out of effect and asks for a new acceptance.

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
		return nil, nil, fmt.Errorf("%w: a person follows a program", shared.ErrForbidden)
	}
	if s.catalog == nil {
		return nil, nil, bp.ErrNotFound
	}
	pub, err := s.catalog.GetPublic(ctx, publicID)
	if err != nil {
		return nil, nil, err
	}
	if pub.RemovedAt != nil || !pub.Open() {
		return nil, nil, bp.ErrPublicProgramGone
	}
	items := pub.ItemsFor(nil)
	pv, err := s.previewItems(ctx, tenantID, pub.ProgramURL(), pub.TermsText, pub.Rules, items, nil)
	if err != nil {
		return nil, nil, err
	}
	now := s.now()
	pid := pub.ID
	p := &bp.Program{
		ID: shared.NewID(), TenantID: tenantID, Name: clip(pub.Name, bp.MaxNameLength), Platform: clip(pub.Platform, bp.MaxPlatformLength),
		Handle: clip(pub.Handle, bp.MaxHandleLength), ProgramURL: pub.ProgramURL(), Visibility: bp.VisibilityPublic,
		TermsText: pub.TermsText, Status: bp.StatusPendingAttestation, ScopeSource: bp.ScopeSourcePublicFeed,
		Rules: pv.rules, ScopeItems: items, TermsSHA256: pv.TermsSHA256, PublicProgramID: &pid,
		PublicSyncedSHA256: pub.TermsSHA256, CreatedBy: &actor, CreatedAt: now, UpdatedAt: now,
	}
	entries, err := s.newEntries(p, pv, actor, false)
	if err != nil {
		return nil, nil, err
	}
	member := actor
	group := bp.NewGroup{ID: shared.NewID(), Name: clip("Program: "+p.Name, 100),
		Slug: "program-" + strings.ReplaceAll(p.ID.String(), "-", "")[:16], Member: &member}
	// Inactive entries authorize nothing: the ledger hook is told of no
	// entry put into effect.
	if err := s.commit(ctx, tenantID, actor, nil, nil, func() error {
		return s.repo.Import(ctx, bp.ImportWrite{Program: p, Group: group, Entries: entries, Exclusions: s.exclusions(p, pv)})
	}); err != nil {
		return nil, nil, err
	}
	s.assign(ctx, p)
	return p, pv, nil
}

// ConfirmTargets turns targets the feed only suggested (inferred) into the
// program's scope, on a member's confirmation. It widens the program: every
// entry waits for a new acceptance of the terms.
func (s *Service) ConfirmTargets(ctx context.Context, tenantID, actor, id shared.ID, targets []string) (*bp.Program, *Preview, error) {
	if actor.IsZero() {
		return nil, nil, fmt.Errorf("%w: a person confirms targets", shared.ErrForbidden)
	}
	p, err := s.loadAttested(ctx, tenantID, actor, id)
	if err != nil {
		return nil, nil, err
	}
	if p.PublicProgramID == nil || s.catalog == nil {
		return nil, nil, fmt.Errorf("%w: only a followed public program has suggested targets", shared.ErrValidation)
	}
	if p.Status == bp.StatusEnded {
		return nil, nil, bp.ErrEnded
	}
	if len(targets) == 0 || len(targets) > bp.MaxScopeItems {
		return nil, nil, fmt.Errorf("%w: confirm 1 to %d targets", shared.ErrValidation, bp.MaxScopeItems)
	}
	pub, err := s.catalog.GetPublic(ctx, *p.PublicProgramID)
	if err != nil {
		return nil, nil, err
	}
	have := map[string]bool{}
	for _, c := range p.ConfirmedTargets {
		have[strings.ToLower(c)] = true
	}
	for _, t := range targets {
		t = strings.TrimSpace(t)
		if !pub.IsSuggestion(t) {
			return nil, nil, bp.ErrNotInferred
		}
		if !have[strings.ToLower(t)] {
			have[strings.ToLower(t)] = true
			p.ConfirmedTargets = append(p.ConfirmedTargets, t)
		}
	}
	items := pub.ItemsFor(p.ConfirmedTargets)
	pv, err := s.previewItems(ctx, tenantID, pub.ProgramURL(), pub.TermsText, pub.Rules, items, p)
	if err != nil {
		return nil, nil, err
	}
	if err := s.replaceAwaitingAcceptance(ctx, p, pub, items, pv); err != nil {
		return nil, nil, err
	}
	return p, pv, nil
}

// ApplyFeedChange brings one followed program up to date with its catalog
// program (the importer's reconcile). It returns what it did: "synced",
// "narrowed", "needs_acceptance" or "suspended".
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
	if pub.RemovedAt != nil || !pub.Open() {
		// A closed, paused or archived program stops monitoring.
		if p.Status == bp.StatusActive {
			p.PublicSyncedSHA256 = pub.TermsSHA256
			if err := s.suspend(ctx, p, shared.ID{}, "the program is closed, paused or no longer published"); err != nil {
				return "", err
			}
			return "suspended", nil
		}
		return s.markSynced(ctx, p, pub)
	}
	items := pub.ItemsFor(p.ConfirmedTargets)
	pv, err := s.previewItems(ctx, p.TenantID, pub.ProgramURL(), pub.TermsText, pub.Rules, items, p)
	if err != nil {
		return "", err
	}
	if pv.TermsSHA256 == p.TermsSHA256 {
		return s.markSynced(ctx, p, pub)
	}
	diff := bp.DiffPlans(bp.PlanScope(p.ScopeItems), bp.PlanScope(items))
	rulesChanged := bp.NewTerms(pub.ProgramURL(), pub.Rules, nil).WithText(pub.TermsText).SHA256() !=
		bp.NewTerms(p.ProgramURL, p.Rules, nil).WithText(p.TermsText).SHA256()
	if !diff.Widens() && !rulesChanged && p.Status != bp.StatusPendingAttestation {
		// Only narrowing: applied at once (saved with the program row), the
		// program stays in effect.
		p.ScopeItems, p.TermsSHA256, p.PublicSyncedSHA256, p.UpdatedAt = items, pv.TermsSHA256, pub.TermsSHA256, s.now()
		if err := s.narrow(ctx, p, diff); err != nil {
			return "", err
		}
		s.audited(ctx, p, shared.ID{}, "Program scope narrowed by the program feed", map[string]any{
			"entries_removed": len(diff.RemovedEntries), "exclusions_added": len(diff.AddedExclusion)})
		return "narrowed", nil
	}
	if err := s.replaceAwaitingAcceptance(ctx, p, pub, items, pv); err != nil {
		return "", err
	}
	return "needs_acceptance", nil
}

// markSynced records that the program reflects the catalog content.
func (s *Service) markSynced(ctx context.Context, p *bp.Program, pub *bp.PublicProgram) (string, error) {
	if p.PublicSyncedSHA256 == pub.TermsSHA256 {
		return "", nil
	}
	excl, err := s.repo.Exclusions(ctx, p.TenantID, &p.ID)
	if err != nil {
		return "", err
	}
	p.PublicSyncedSHA256, p.UpdatedAt = pub.TermsSHA256, s.now()
	// No entry changes: the same program exclusions are written back.
	if err := s.commit(ctx, p.TenantID, shared.ID{}, nil, nil, func() error {
		return s.repo.ReplaceScope(ctx, bp.ScopeWrite{Program: p, Exclusions: excl})
	}); err != nil {
		return "", err
	}
	return "synced", nil
}

// replaceAwaitingAcceptance replaces a followed program's scope, rules and
// terms and takes every entry out of effect in one transaction: status
// pending_attestation until a member accepts. Members are notified.
func (s *Service) replaceAwaitingAcceptance(ctx context.Context, p *bp.Program, pub *bp.PublicProgram, items []bp.Item, pv *Preview) error {
	current, err := s.repo.Entries(ctx, p.TenantID, p.ID)
	if err != nil {
		return err
	}
	keep := map[string]bool{}
	for _, e := range pv.Entries {
		if e.Status == PlanKeep {
			keep[entryKey(e.TargetType, e.Pattern, e.Constraint)] = true
		}
	}
	var drop []shared.ID
	stopped := make([]shared.ID, 0, len(current))
	for _, e := range current {
		stopped = append(stopped, e.ID())
		if !keep[entryKey(e.TargetType(), e.Pattern(), e.Constraint())] {
			drop = append(drop, e.ID())
		}
	}
	added := 0
	for _, e := range pv.Entries {
		if e.Status == PlanCreate {
			added++
		}
	}
	now := s.now()
	p.Status, p.Rules, p.ScopeItems, p.TermsText, p.TermsSHA256 = bp.StatusPendingAttestation, pv.rules, items, pub.TermsText, pv.TermsSHA256
	p.ProgramURL, p.PublicSyncedSHA256, p.Pending, p.UpdatedAt = pub.ProgramURL(), pub.TermsSHA256, nil, now
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
	s.audited(ctx, p, shared.ID{}, "Program scope or terms changed; entries wait for a new acceptance",
		map[string]any{"entries_created": len(create), "entries_removed": len(drop)})
	s.assign(ctx, p)
	if s.notifier != nil {
		body := fmt.Sprintf("%s changed its scope or terms; a member must accept the new terms before its targets are scanned actively", p.Name)
		if added > 0 {
			body = fmt.Sprintf("%s lists %d new in-scope targets; a member must accept the new terms before they are scanned actively", p.Name, added)
		}
		s.notifier.NotifyAdmins(ctx, p.TenantID, "Program scope changed: accept the terms again", body)
	}
	return nil
}
