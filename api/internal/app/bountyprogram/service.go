// Package bountyprogram imports and runs the bug-bounty programs an
// organization follows (RFC-065, docs/architecture/bounty-programs.md).
//
// A program's scope entries take effect on the importer's attestation of
// the program's terms (program URL, rules, in and out of scope, hashed);
// they never go through the organization's approval policy, and the program
// routes never create or widen any other kind of entry. Every change is
// tenant-scoped; a person who is neither a member of the program's group nor
// a full-data caller gets "not found" for it.
package bountyprogram

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	bp "github.com/openctemio/openctem/api/pkg/domain/bountyprogram"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// FullData answers whether the caller sees the whole organization
// (*datascope.Enforcer.FullDataCaller: owners, admins, full-data roles).
type FullData interface {
	FullDataCaller(ctx context.Context, tenantID shared.ID) (bool, error)
}

// AdminNotifier tells every administrator about a widening (*scope.Service).
type AdminNotifier interface {
	NotifyAdmins(ctx context.Context, tenantID shared.ID, title, body string)
}

// Ledger feeds the job signer's scope ledger (*scope.Service.CommitEntries):
// entries put in effect go to the signer before save, removed ones after.
type Ledger interface {
	CommitEntries(ctx context.Context, tenantID shared.ID, requester string, put []*scopedom.Target,
		removed []shared.ID, platformPolicy string, save func() error) error
}

// Joiner runs the scope join after entries change (*easm.JoinScheduler).
type Joiner interface {
	Schedule(tenantID shared.ID)
}

// Service imports and manages programs.
type Service struct {
	repo       bp.Repository
	fullData   FullData
	guardrails scopedom.Guardrails
	notifier   AdminNotifier
	joiner     Joiner
	ledger     Ledger
	log        *logger.Logger
	now        func() time.Time
}

// NewService wires the service. Without a FullData checker every caller is
// restricted to their own programs (fail closed).
func NewService(repo bp.Repository, fullData FullData, log *logger.Logger) *Service {
	if log == nil {
		log = logger.NewNop()
	}
	return &Service{repo: repo, fullData: fullData, guardrails: scopedom.DefaultGuardrails(),
		log: log.With("service", "bounty-programs"), now: func() time.Time { return time.Now().UTC() }}
}

// SetGuardrails sets the operator's scope guardrails (RFC-054 §8).
func (s *Service) SetGuardrails(g scopedom.Guardrails) { s.guardrails = g }

// SetNotifier wires the administrator notification.
func (s *Service) SetNotifier(n AdminNotifier) { s.notifier = n }

// SetJoiner wires the scope join.
func (s *Service) SetJoiner(j Joiner) { s.joiner = j }

// SetLedger wires the job signer's scope ledger (RFC-040 §11.5).
func (s *Service) SetLedger(l Ledger) { s.ledger = l }

// programAttestation labels the policy of a program widening: the
// importer attests the published terms; no approver (RFC-065).
const programAttestation = "program_attestation"

// commit runs save through the ledger hook (or alone without one).
func (s *Service) commit(ctx context.Context, tenantID, actor shared.ID, put []*scopedom.Target, removed []shared.ID, save func() error) error {
	if s.ledger == nil {
		return save()
	}
	requester := ""
	if !actor.IsZero() {
		requester = actor.String()
	}
	return s.ledger.CommitEntries(ctx, tenantID, requester, put, removed, programAttestation, save)
}

// entryIDs are the ids of entries.
func entryIDs(entries []*scopedom.Target) []shared.ID {
	out := make([]shared.ID, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.ID())
	}
	return out
}

// Input is the body of a preview, an import and a re-import.
type Input struct {
	Name       string
	Platform   string
	Handle     string
	ProgramURL string
	ScopeText  string
	Rules      bp.Rules
	// AcceptTermsSHA256 is the attestation: the terms hash from the preview.
	AcceptTermsSHA256 string
}

// Entry statuses in a preview.
const (
	PlanCreate         = "create"
	PlanKeep           = "keep"
	PlanAlreadyCovered = "already_covered"
	PlanRefused        = "refused"
)

// PlannedEntry is one in-scope item and what the import does with it.
type PlannedEntry struct {
	TargetType scopedom.TargetType `json:"target_type"`
	Pattern    string              `json:"pattern"`
	Status     string              `json:"status"`
	// Code is the guardrail refusal (PUBLIC_SUFFIX, DENY_LIST, ...).
	Code string `json:"code,omitempty"`
	// Source is the source of the existing entry an already covered item
	// matches.
	Source string `json:"source,omitempty"`
}

// Overlap names the organization's own entry that also covers a program
// exclusion (RFC-065 B7).
type Overlap struct {
	EntryID string `json:"entry_id"`
	Pattern string `json:"pattern"`
	Source  string `json:"source"`
}

// PlannedExclusion is one program exclusion.
type PlannedExclusion struct {
	TargetType scopedom.TargetType `json:"target_type"`
	Pattern    string              `json:"pattern"`
	Reason     string              `json:"reason"`
	// InScopeBy is set when an entry of the organization's own scope covers
	// the name: the program excludes it, ownership still authorizes it.
	InScopeBy *Overlap `json:"in_scope_by,omitempty"`
}

// Preview is what an import would do.
type Preview struct {
	Items        []bp.Item          `json:"items"`
	Entries      []PlannedEntry     `json:"entries"`
	Exclusions   []PlannedExclusion `json:"exclusions"`
	NotScannable []bp.Item          `json:"not_scannable"`
	MaxTier      string             `json:"max_tier"`
	TermsSHA256  string             `json:"terms_sha256"`
	rules        bp.Rules
}

// Preview parses and checks an import or re-import without writing. For a
// re-import, program is the program being replaced (its own entries are
// "keep"); nil for a new program.
func (s *Service) Preview(ctx context.Context, tenantID shared.ID, in Input, program *bp.Program) (*Preview, error) {
	name := in.Name
	if program != nil {
		name = program.Name
	}
	if err := bp.ValidateDetails(name, in.Platform, in.Handle, in.ProgramURL); err != nil {
		return nil, err
	}
	rules := in.Rules.Normalize()
	if err := rules.Validate(); err != nil {
		return nil, err
	}
	items, err := bp.ParseScope(in.ScopeText)
	if err != nil {
		return nil, err
	}
	plan := bp.PlanScope(items)
	existing, err := s.repo.TenantEntries(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	byKey := make(map[string]*scopedom.Target, len(existing))
	for _, t := range existing {
		byKey[entryKey(t.TargetType(), t.Pattern())] = t
	}
	out := &Preview{Items: items, NotScannable: plan.NotScannable, MaxTier: rules.MaxTier().String(),
		TermsSHA256: bp.NewTerms(in.ProgramURL, rules, items).SHA256(), rules: rules,
		Entries: make([]PlannedEntry, 0, len(plan.Entries)), Exclusions: make([]PlannedExclusion, 0, len(plan.Exclusions))}
	for _, e := range plan.Entries {
		pe := PlannedEntry{TargetType: e.TargetType, Pattern: e.Pattern, Status: PlanCreate}
		if err := s.guardrails.CheckPattern(e.TargetType, e.Pattern); err != nil {
			pe.Status, pe.Code = PlanRefused, refusalCode(err)
		} else if t := byKey[entryKey(e.TargetType, e.Pattern)]; t != nil {
			if program != nil && t.ProgramID() != nil && t.ProgramID().Equals(program.ID) {
				pe.Status = PlanKeep
			} else {
				pe.Status, pe.Source = PlanAlreadyCovered, string(t.AuthorizationSource())
			}
		}
		out.Entries = append(out.Entries, pe)
	}
	for _, x := range plan.Exclusions {
		out.Exclusions = append(out.Exclusions, PlannedExclusion{TargetType: x.TargetType, Pattern: x.Pattern,
			Reason: x.Reason, InScopeBy: ownershipOverlap(existing, x.TargetType, x.Pattern)})
	}
	return out, nil
}

func entryKey(t scopedom.TargetType, pattern string) string {
	return string(t) + "|" + strings.ToLower(pattern)
}

func refusalCode(err error) string {
	var de *shared.DomainError
	if errors.As(err, &de) && de.Code != "" {
		return de.Code
	}
	return "REFUSED"
}

// ownershipOverlap returns the organization's own active entry (not a
// program entry) that covers an exclusion pattern.
func ownershipOverlap(entries []*scopedom.Target, t scopedom.TargetType, pattern string) *Overlap {
	for _, e := range entries {
		if e.IsProgramEntry() || !e.IsActive() {
			continue
		}
		if sameFamily(e.TargetType(), t) && e.Matches(pattern) {
			return &Overlap{EntryID: e.ID().String(), Pattern: e.Pattern(), Source: string(e.AuthorizationSource())}
		}
	}
	return nil
}

// sameFamily: domain patterns are compared with domain entries, addresses
// with address entries.
func sameFamily(a, b scopedom.TargetType) bool {
	dom := func(t scopedom.TargetType) bool {
		return t == scopedom.TargetTypeDomain || t == scopedom.TargetTypeSubdomain
	}
	ip := func(t scopedom.TargetType) bool {
		return t == scopedom.TargetTypeIPAddress || t == scopedom.TargetTypeCIDR || t == scopedom.TargetTypeIPRange
	}
	return (dom(a) && dom(b)) || (ip(a) && ip(b)) || a == b
}

// checkTerms is the attestation: the caller accepted exactly these terms.
func checkTerms(accepted, computed string) error {
	switch strings.TrimSpace(accepted) {
	case "":
		return bp.ErrTermsRequired
	case computed:
		return nil
	}
	return bp.ErrTermsChanged
}

// newEntries builds the program entries the preview marks "create".
func (s *Service) newEntries(p *bp.Program, pv *Preview, actor shared.ID, active bool) ([]*scopedom.Target, error) {
	out := make([]*scopedom.Target, 0, len(pv.Entries))
	reason := clip(fmt.Sprintf("Program %s (%s)", p.Name, p.ProgramURL), scopedom.MaxReasonLength)
	for _, e := range pv.Entries {
		if e.Status != PlanCreate {
			continue
		}
		t, err := scopedom.NewEntry(p.TenantID, e.TargetType, e.Pattern, "Program: "+clip(p.Name, 200), actor.String(),
			scopedom.EntryOptions{Reason: reason, MaxTier: pv.rules.MaxTier(), Now: s.now()})
		if err != nil {
			return nil, fmt.Errorf("entry %s: %w", e.Pattern, err)
		}
		if err := t.SetAuthorization(scopedom.AuthProgram, &p.ID); err != nil {
			return nil, err
		}
		if !active {
			t.Deactivate()
		}
		out = append(out, t)
	}
	return out, nil
}

func (s *Service) exclusions(p *bp.Program, pv *Preview) []bp.Exclusion {
	out := make([]bp.Exclusion, 0, len(pv.Exclusions))
	for _, x := range pv.Exclusions {
		out = append(out, bp.Exclusion{ID: shared.NewID(), TenantID: p.TenantID, ProgramID: p.ID,
			TargetType: x.TargetType, Pattern: x.Pattern, Reason: x.Reason, CreatedAt: s.now()})
	}
	return out
}

// Import creates a program from an attested preview: the program, its
// group (the importer joins it), its entries (active at once) and its
// program exclusions. The route requires attack_surface:programs:write and
// step-up.
func (s *Service) Import(ctx context.Context, tenantID, actor shared.ID, in Input) (*bp.Program, *Preview, error) {
	if actor.IsZero() {
		return nil, nil, fmt.Errorf("%w: a person imports a program", shared.ErrForbidden)
	}
	pv, err := s.Preview(ctx, tenantID, in, nil)
	if err != nil {
		return nil, nil, err
	}
	if err := checkTerms(in.AcceptTermsSHA256, pv.TermsSHA256); err != nil {
		return nil, nil, err
	}
	now := s.now()
	p := &bp.Program{
		ID: shared.NewID(), TenantID: tenantID, Name: strings.TrimSpace(in.Name),
		Platform: strings.TrimSpace(in.Platform), Handle: strings.TrimSpace(in.Handle),
		ProgramURL: strings.TrimSpace(in.ProgramURL), Status: bp.StatusActive, ScopeSource: bp.ScopeSourcePaste,
		Rules: pv.rules, ScopeItems: pv.Items, TermsSHA256: pv.TermsSHA256,
		AcceptedBy: &actor, AcceptedAt: &now, CreatedBy: &actor, CreatedAt: now, UpdatedAt: now,
	}
	entries, err := s.newEntries(p, pv, actor, true)
	if err != nil {
		return nil, nil, err
	}
	member := actor
	group := bp.NewGroup{ID: shared.NewID(), Name: clip("Program: "+p.Name, 100),
		Slug: "program-" + strings.ReplaceAll(p.ID.String(), "-", "")[:16], Member: &member}
	if err := s.commit(ctx, tenantID, actor, entries, nil, func() error {
		return s.repo.Import(ctx, bp.ImportWrite{Program: p, Group: group, Entries: entries, Exclusions: s.exclusions(p, pv)})
	}); err != nil {
		return nil, nil, err
	}
	s.widened(ctx, p, fmt.Sprintf("Program %s imported with %d scope entries (attested by the importer)", p.Name, len(entries)), len(entries) > 0)
	return p, pv, nil
}

// Access errors.
var errNotFound = bp.ErrNotFound

// loadForCaller returns a program the caller may see: a full-data caller
// sees every program of the tenant; anyone else only the programs whose
// group has them. Anything else is not found.
func (s *Service) loadForCaller(ctx context.Context, tenantID, actor, id shared.ID) (*bp.Program, error) {
	p, err := s.repo.GetByID(ctx, tenantID, id)
	if err != nil {
		return nil, err
	}
	full, err := s.isFullData(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if full {
		return p, nil
	}
	if actor.IsZero() {
		return nil, errNotFound
	}
	ok, err := s.repo.IsMember(ctx, tenantID, id, actor)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errNotFound
	}
	return p, nil
}

func (s *Service) isFullData(ctx context.Context, tenantID shared.ID) (bool, error) {
	if s.fullData == nil {
		return false, nil
	}
	return s.fullData.FullDataCaller(ctx, tenantID)
}

// List lists the programs the caller may see.
func (s *Service) List(ctx context.Context, tenantID, actor shared.ID) ([]*bp.Program, error) {
	full, err := s.isFullData(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if full {
		return s.repo.List(ctx, tenantID, nil)
	}
	if actor.IsZero() {
		return nil, nil
	}
	return s.repo.List(ctx, tenantID, &actor)
}

// Detail is a program with its entries and program exclusions.
type Detail struct {
	Program    *bp.Program
	Entries    []*scopedom.Target
	Exclusions []PlannedExclusion
}

// Get returns a program the caller may see.
func (s *Service) Get(ctx context.Context, tenantID, actor, id shared.ID) (*Detail, error) {
	p, err := s.loadForCaller(ctx, tenantID, actor, id)
	if err != nil {
		return nil, err
	}
	entries, err := s.repo.Entries(ctx, tenantID, id)
	if err != nil {
		return nil, err
	}
	ex, err := s.repo.Exclusions(ctx, tenantID, &id)
	if err != nil {
		return nil, err
	}
	all, err := s.repo.TenantEntries(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	d := &Detail{Program: p, Entries: entries, Exclusions: make([]PlannedExclusion, 0, len(ex))}
	for _, x := range ex {
		d.Exclusions = append(d.Exclusions, PlannedExclusion{TargetType: x.TargetType, Pattern: x.Pattern, Reason: x.Reason,
			InScopeBy: ownershipOverlap(all, x.TargetType, x.Pattern)})
	}
	return d, nil
}

// Reimport replaces a program's scope and rules with a new attested paste:
// entries of items no longer listed are deleted at once, new ones created
// (active when the program is active), program exclusions replaced. The
// route requires attack_surface:programs:write and step-up.
func (s *Service) Reimport(ctx context.Context, tenantID, actor, id shared.ID, in Input) (*bp.Program, *Preview, error) {
	p, err := s.loadForCaller(ctx, tenantID, actor, id)
	if err != nil {
		return nil, nil, err
	}
	if p.Status == bp.StatusEnded {
		return nil, nil, bp.ErrEnded
	}
	if actor.IsZero() {
		return nil, nil, fmt.Errorf("%w: a person re-imports a program", shared.ErrForbidden)
	}
	pv, err := s.Preview(ctx, tenantID, in, p)
	if err != nil {
		return nil, nil, err
	}
	if err := checkTerms(in.AcceptTermsSHA256, pv.TermsSHA256); err != nil {
		return nil, nil, err
	}
	current, err := s.repo.Entries(ctx, tenantID, id)
	if err != nil {
		return nil, nil, err
	}
	keep := map[string]bool{}
	for _, e := range pv.Entries {
		if e.Status == PlanKeep {
			keep[entryKey(e.TargetType, e.Pattern)] = true
		}
	}
	var drop []shared.ID
	for _, e := range current {
		if !keep[entryKey(e.TargetType(), e.Pattern())] {
			drop = append(drop, e.ID())
		}
	}
	now := s.now()
	p.ProgramURL, p.Rules, p.ScopeItems, p.TermsSHA256 = strings.TrimSpace(in.ProgramURL), pv.rules, pv.Items, pv.TermsSHA256
	p.AcceptedBy, p.AcceptedAt, p.UpdatedAt = &actor, &now, now
	if strings.TrimSpace(in.Platform) != "" {
		p.Platform = strings.TrimSpace(in.Platform)
	}
	if strings.TrimSpace(in.Handle) != "" {
		p.Handle = strings.TrimSpace(in.Handle)
	}
	create, err := s.newEntries(p, pv, actor, p.Status == bp.StatusActive)
	if err != nil {
		return nil, nil, err
	}
	if err := s.commit(ctx, tenantID, actor, create, drop, func() error {
		return s.repo.ReplaceScope(ctx, bp.ScopeWrite{Program: p, CreateEntries: create, DeleteEntryIDs: drop,
			Exclusions: s.exclusions(p, pv)})
	}); err != nil {
		return nil, nil, err
	}
	s.widened(ctx, p, fmt.Sprintf("Program %s re-imported: %d entries added, %d removed (attested)", p.Name, len(create), len(drop)),
		len(create) > 0 && p.Status == bp.StatusActive)
	return p, pv, nil
}

// Pause stops every entry of the program (narrowing).
func (s *Service) Pause(ctx context.Context, tenantID, actor, id shared.ID) (*bp.Program, error) {
	p, err := s.loadForCaller(ctx, tenantID, actor, id)
	if err != nil {
		return nil, err
	}
	if p.Status != bp.StatusActive {
		return nil, bp.ErrNotActive
	}
	p.Status, p.UpdatedAt = bp.StatusPaused, s.now()
	if err := s.stopEntries(ctx, p, actor); err != nil {
		return nil, err
	}
	return p, nil
}

// End stops every entry of the program for good (narrowing).
func (s *Service) End(ctx context.Context, tenantID, actor, id shared.ID) (*bp.Program, error) {
	p, err := s.loadForCaller(ctx, tenantID, actor, id)
	if err != nil {
		return nil, err
	}
	if p.Status == bp.StatusEnded {
		return nil, bp.ErrEnded
	}
	p.Status, p.UpdatedAt = bp.StatusEnded, s.now()
	if err := s.stopEntries(ctx, p, actor); err != nil {
		return nil, err
	}
	return p, nil
}

// Resume puts a paused program's entries back into effect on a new
// attestation of its current terms. The route requires step-up.
func (s *Service) Resume(ctx context.Context, tenantID, actor, id shared.ID, acceptTerms string) (*bp.Program, error) {
	p, err := s.loadForCaller(ctx, tenantID, actor, id)
	if err != nil {
		return nil, err
	}
	switch p.Status {
	case bp.StatusEnded:
		return nil, bp.ErrEnded
	case bp.StatusActive:
		return nil, fmt.Errorf("%w: the program is already active", shared.ErrConflict)
	}
	if actor.IsZero() {
		return nil, fmt.Errorf("%w: a person resumes a program", shared.ErrForbidden)
	}
	if err := checkTerms(acceptTerms, p.TermsSHA256); err != nil {
		return nil, err
	}
	now := s.now()
	p.Status, p.AcceptedBy, p.AcceptedAt, p.UpdatedAt = bp.StatusActive, &actor, &now, now
	entries, err := s.repo.Entries(ctx, tenantID, id)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if e.Status() == scopedom.StatusInactive {
			e.Activate() // as SetStatus puts it, for the ledger
		}
	}
	if err := s.commit(ctx, tenantID, actor, entries, nil, func() error {
		return s.repo.SetStatus(ctx, p, scopedom.StatusActive)
	}); err != nil {
		return nil, err
	}
	s.widened(ctx, p, fmt.Sprintf("Program %s resumed (attested)", p.Name), true)
	return p, nil
}

// stopEntries takes every entry of p out of effect (narrowing).
func (s *Service) stopEntries(ctx context.Context, p *bp.Program, actor shared.ID) error {
	entries, err := s.repo.Entries(ctx, p.TenantID, p.ID)
	if err != nil {
		return err
	}
	return s.commit(ctx, p.TenantID, actor, nil, entryIDs(entries), func() error {
		return s.repo.SetStatus(ctx, p, scopedom.StatusInactive)
	})
}

// widened notifies the administrators and schedules the scope join.
func (s *Service) widened(ctx context.Context, p *bp.Program, body string, join bool) {
	if s.notifier != nil {
		s.notifier.NotifyAdmins(ctx, p.TenantID, "Program scope in effect", body)
	}
	if join && s.joiner != nil {
		s.joiner.Schedule(p.TenantID)
	}
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
