package scope

// Scope entries on provider shared addresses (research/531 §6 step 4, D3,
// D13, D14; docs/architecture/provider-shared-addresses.md).
//
// An address, CIDR or range entry that lies wholly inside a range a provider
// publishes for a front end many organizations share (a Microsoft 365 mail
// front end, an Amazon CloudFront or Cloudflare edge) names the provider's
// infrastructure. The Scope page lists such entries once per provider and
// asks one question:
//
//   - Move to out of scope (recommended): every listed entry becomes a
//     do_not_scan exclusion of the same pattern, with the entry's origin,
//     and the entry is deactivated, in one transaction and one narrowing
//     signer ledger change. Narrowing needs scope:write and no step-up. The
//     exclusion stays on the address: names that resolve to it are not
//     excluded with it (PropagatingAddresses, owner decision 2026-10-30).
//   - Keep scanning: the organization's recorded decision, per entry, with
//     step-up; the entries leave the card and are never held.
//
// While the tenant's scope setting hold_provider_entries is on (the
// default, owner decision 2026-11-19), an entry nobody answered authorizes
// no active check (HeldProviderEntries, read by scopeauth.Load): the gate
// answers provider_held and the Scope page says why. Keep scanning restores
// active checks of those entries in one step; an organization can also turn
// the hold off in its scope settings.
//
// Person-confirmed provider addresses (an ip_address asset inside a shared
// range whose attribution a person decided) are listed under the card for
// review: keep or move. They are read within the caller's data scope.

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/openctemio/openctem/server/pkg/domain/edgeaddr"
	scopedom "github.com/openctemio/openctem/server/pkg/domain/scope"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/jobsign"
)

// ProviderAddressStore keeps the card's decisions and writes a move
// (*postgres.ScopeProviderRepository). Every method is tenant-scoped.
type ProviderAddressStore interface {
	// KeptEntryIDs are the tenant's entries a person chose to keep scanning.
	KeptEntryIDs(ctx context.Context, tenantID shared.ID) (map[shared.ID]bool, error)
	// SaveKeeps records keep-scanning decisions on the tenant's entries
	// (idempotent per entry).
	SaveKeeps(ctx context.Context, tenantID shared.ID, keeps []ProviderKeep) error
	// SaveMove creates the exclusions and saves the deactivated entries in
	// one transaction: all of it or none of it.
	SaveMove(ctx context.Context, tenantID shared.ID, exclusions []*scopedom.Exclusion, deactivated []*scopedom.Target) error
	// PersonConfirmedAddresses lists the tenant's ip_address assets whose
	// attribution a person decided as confirmed, within the data scope ds
	// (nil: the whole tenant).
	PersonConfirmedAddresses(ctx context.Context, tenantID shared.ID, ds *shared.DataScope) ([]ProviderConfirmed, error)
}

// ProviderKeep is one keep-scanning decision.
type ProviderKeep struct {
	TargetID       shared.ID
	Provider       string
	DatasetVersion string
	DecidedBy      string
}

// SetProviderAddresses wires the store of the provider addresses card.
func (s *Service) SetProviderAddresses(st ProviderAddressStore) { s.providers = st }

// ErrProviderAddressesUnavailable: the card's store is not wired.
var ErrProviderAddressesUnavailable = errors.New("provider addresses are not configured")

// CodeProviderNotListed is the code of ErrProviderUnknown.
const CodeProviderNotListed = "PROVIDER_NOT_LISTED"

// ErrProviderUnknown: no listed entry names this provider (nothing to do,
// or another tenant's provider list; the answer is the same).
var ErrProviderUnknown = shared.NewDomainError(CodeProviderNotListed,
	"No scope entry of this provider is waiting for an answer", shared.ErrNotFound)

// ProviderEntry is one scope entry on a provider's shared addresses.
type ProviderEntry struct {
	ID         string
	TargetType string
	Pattern    string
	Origin     string
	Status     string
	CreatedAt  time.Time
}

// ProviderConfirmed is an address a person confirmed as the organization's
// that lies inside a provider's shared range.
type ProviderConfirmed struct {
	AssetID   string
	Name      string
	DecidedAt *time.Time
}

// ProviderGroup is one provider's row of the card.
type ProviderGroup struct {
	Provider  string
	Class     string
	Entries   []ProviderEntry
	Confirmed []ProviderConfirmed
}

// ProviderCard is what the Scope page shows: one group per provider with
// something to decide, the dataset version the classification used, and
// whether the organization holds unanswered entries.
type ProviderCard struct {
	DatasetVersion string
	Holding        bool
	Groups         []ProviderGroup
}

// providerEntry pairs an entry with its provider.
type providerEntry struct {
	t *scopedom.Target
	r edgeaddr.Result
}

// unansweredProviderEntries are the tenant's in-effect entries on shared
// provider addresses that nobody answered. Program entries are another
// organization's scope (RFC-065) and never listed.
func (s *Service) unansweredProviderEntries(ctx context.Context, tenantID shared.ID, targets []*scopedom.Target) ([]providerEntry, error) {
	var out []providerEntry
	for _, t := range targets {
		if t == nil || t.ProgramID() != nil || t.IsProgramEntry() {
			continue
		}
		if r, ok := scopedom.SharedProviderEntry(t.TargetType(), t.Pattern()); ok {
			out = append(out, providerEntry{t: t, r: r})
		}
	}
	if len(out) == 0 {
		return nil, nil
	}
	if s.providers == nil {
		return out, nil // no decisions can exist: every entry is unanswered
	}
	kept, err := s.providers.KeptEntryIDs(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("read kept provider entries: %w", err)
	}
	keep := out[:0]
	for _, e := range out {
		if !kept[e.t.ID()] {
			keep = append(keep, e)
		}
	}
	return keep, nil
}

// HeldProviderEntries implements scopeauth.ProviderHolds: while the tenant's
// hold_provider_entries setting is on (the default), its unanswered entries
// on shared provider addresses authorize nothing. Without a settings reader
// the default applies; settings that cannot be read refuse (the caller's
// gate then dispatches nothing).
func (s *Service) HeldProviderEntries(ctx context.Context, tenantID shared.ID, targets []*scopedom.Target) (map[shared.ID]bool, error) {
	if s.settings != nil {
		ss, err := s.settings.GetScopeSettings(ctx, tenantID.String())
		if err != nil {
			return nil, fmt.Errorf("read scope settings: %w", err)
		}
		if ss != nil && !ss.HoldsProviderEntries() {
			return nil, nil
		}
	}
	entries, err := s.unansweredProviderEntries(ctx, tenantID, targets)
	if err != nil {
		return nil, err
	}
	out := make(map[shared.ID]bool, len(entries))
	for _, e := range entries {
		out[e.t.ID()] = true
	}
	return out, nil
}

// holding reports the tenant's hold_provider_entries setting (the default,
// on, without a reader or a stored value; on when it cannot be read, as the
// gate then refuses anyway).
func (s *Service) holding(ctx context.Context, tenantID shared.ID) bool {
	if s.settings == nil {
		return true
	}
	ss, err := s.settings.GetScopeSettings(ctx, tenantID.String())
	return err != nil || ss == nil || ss.HoldsProviderEntries()
}

// ProviderAddresses is the card: per provider, the unanswered entries and
// the person-confirmed addresses (within the caller's data scope).
func (s *Service) ProviderAddresses(ctx context.Context, tenantID string) (*ProviderCard, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	targets, err := s.ListActiveTargets(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	entries, err := s.unansweredProviderEntries(ctx, tid, targets)
	if err != nil {
		return nil, err
	}
	groups := map[string]*ProviderGroup{}
	group := func(r edgeaddr.Result) *ProviderGroup {
		g := groups[r.Provider]
		if g == nil {
			g = &ProviderGroup{Provider: r.Provider, Class: string(r.Class), Entries: []ProviderEntry{}, Confirmed: []ProviderConfirmed{}}
			groups[r.Provider] = g
		}
		return g
	}
	for _, e := range entries {
		g := group(e.r)
		g.Entries = append(g.Entries, providerEntryOf(e.t))
	}
	if s.providers != nil {
		var ds *shared.DataScope
		if s.dataScope == nil {
			return nil, fmt.Errorf("provider addresses: data scope is not configured")
		}
		if ds, err = s.dataScope.Resolve(ctx, tid); err != nil {
			return nil, fmt.Errorf("resolve data scope: %w", err)
		}
		confirmed, err := s.providers.PersonConfirmedAddresses(ctx, tid, ds)
		if err != nil {
			return nil, err
		}
		for _, c := range confirmed {
			if r, ok := edgeaddr.Default().SharedFrontEnd(c.Name); ok {
				g := group(r)
				g.Confirmed = append(g.Confirmed, c)
			}
		}
	}
	out := &ProviderCard{DatasetVersion: edgeaddr.Default().Version(), Holding: s.holding(ctx, tid), Groups: make([]ProviderGroup, 0, len(groups))}
	for _, g := range groups {
		sort.Slice(g.Entries, func(i, j int) bool { return g.Entries[i].Pattern < g.Entries[j].Pattern })
		sort.Slice(g.Confirmed, func(i, j int) bool { return g.Confirmed[i].Name < g.Confirmed[j].Name })
		out.Groups = append(out.Groups, *g)
	}
	sort.Slice(out.Groups, func(i, j int) bool {
		if len(out.Groups[i].Entries) != len(out.Groups[j].Entries) {
			return len(out.Groups[i].Entries) > len(out.Groups[j].Entries)
		}
		return out.Groups[i].Provider < out.Groups[j].Provider
	})
	return out, nil
}

func providerEntryOf(t *scopedom.Target) ProviderEntry {
	return ProviderEntry{ID: t.ID().String(), TargetType: string(t.TargetType()), Pattern: t.Pattern(),
		Origin: string(t.Origin()), Status: string(t.Status()), CreatedAt: t.CreatedAt()}
}

// providerEntriesOf are the tenant's unanswered entries of one provider.
func (s *Service) providerEntriesOf(ctx context.Context, tenantID shared.ID, provider string) ([]providerEntry, error) {
	provider = strings.TrimSpace(provider)
	if provider == "" {
		return nil, fmt.Errorf("%w: provider is required", shared.ErrValidation)
	}
	targets, err := s.ListActiveTargets(ctx, tenantID.String())
	if err != nil {
		return nil, err
	}
	all, err := s.unansweredProviderEntries(ctx, tenantID, targets)
	if err != nil {
		return nil, err
	}
	var out []providerEntry
	for _, e := range all {
		if e.r.Provider == provider {
			out = append(out, e)
		}
	}
	if len(out) == 0 {
		return nil, ErrProviderUnknown
	}
	return out, nil
}

// ProviderMoveInput moves one provider's listed entries out of scope.
type ProviderMoveInput struct {
	TenantID string
	Provider string
	// Actor is the person moving them (the exclusions' creator).
	Actor string
	// Preview answers the counts and writes nothing.
	Preview bool
}

// ProviderMoved is one entry moved: the entry before and after, and the
// exclusion created for it (nil when one with the same pattern existed).
type ProviderMoved struct {
	Before, After *scopedom.Target
	Exclusion     *scopedom.Exclusion
	ExistingID    string
}

// ProviderMoveResult is what a move did, or would do.
type ProviderMoveResult struct {
	Provider string
	Preview  bool
	// Entries: how many entries are moved; Exclusions: how many new
	// exclusions; Existing: entries whose exclusion already existed.
	Entries, Exclusions, Existing int
	Moved                         []ProviderMoved
}

// providerMoveReason is recorded on each exclusion the card creates.
func providerMoveReason(provider string) string {
	return "Shared " + provider + " address: the provider's infrastructure, used by its other customers too. Moved out of scope from the provider addresses card."
}

// MoveProviderOutOfScope turns one provider's listed entries into do_not_scan
// exclusions of the same pattern (origin kept) and deactivates the entries:
// one transaction and one narrowing ledger change. It never excludes the
// names resolving to those addresses. Preview writes nothing.
func (s *Service) MoveProviderOutOfScope(ctx context.Context, in ProviderMoveInput) (*ProviderMoveResult, error) {
	tid, err := shared.IDFromString(in.TenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	if s.providers == nil {
		return nil, ErrProviderAddressesUnavailable
	}
	entries, err := s.providerEntriesOf(ctx, tid, in.Provider)
	if err != nil {
		return nil, err
	}
	res := &ProviderMoveResult{Provider: entries[0].r.Provider, Preview: in.Preview, Entries: len(entries)}
	effective := !s.entriesNeedApproval(ctx, tid)
	now := time.Now().UTC()
	var (
		exclusions []*scopedom.Exclusion
		targets    []*scopedom.Target
	)
	ch := jobsign.LedgerChange{TenantID: tid.String(), ChangeID: uuid.NewString(), Approvals: []jobsign.LedgerApproval{}}
	for _, e := range entries {
		et, err := scopedom.ParseExclusionType(string(e.t.TargetType()))
		if err != nil {
			return nil, err
		}
		x, err := scopedom.NewExclusion(tid, et, e.t.Pattern(), providerMoveReason(res.Provider), nil, in.Actor)
		if err != nil {
			return nil, err
		}
		x.SetKind(scopedom.ExclusionKindDoNotScan)
		x.SetOrigin(e.t.Origin())
		m := ProviderMoved{Before: cloneTarget(e.t)}
		existing, err := s.exclusionRepo.FindByPattern(ctx, tid, et, x.Pattern())
		if err != nil {
			return nil, fmt.Errorf("check existing exclusion: %w", err)
		}
		if existing != nil {
			m.ExistingID = existing.ID.String()
			res.Existing++
		} else {
			if effective {
				if err := x.TakeEffect(in.Actor); err != nil {
					return nil, err
				}
			}
			m.Exclusion = x
			res.Exclusions++
			exclusions = append(exclusions, x)
			if le := ledgerExclusionOf(x, now); le != nil {
				ch.Ops = append(ch.Ops, jobsign.LedgerOp{Op: jobsign.OpPutExclusion, Exclusion: le})
			}
		}
		if before := ledgerEntryOf(e.t, now); before != nil {
			ch.Ops = append(ch.Ops, jobsign.LedgerOp{Op: jobsign.OpRemoveEntry, ID: before.ID})
		}
		after := e.t
		if !in.Preview {
			after.Deactivate()
			targets = append(targets, after)
		}
		m.After = after
		res.Moved = append(res.Moved, m)
	}
	if in.Preview {
		return res, nil
	}
	save := func() error { return s.providers.SaveMove(ctx, tid, exclusions, targets) }
	if s.ledger == nil || len(ch.Ops) == 0 {
		err = save()
	} else {
		err = s.commitLedger(ctx, ch, false, save)
	}
	if err != nil {
		if errors.Is(err, scopedom.ErrExclusionAlreadyExists) {
			return nil, fmt.Errorf("%w: an exclusion was added meanwhile; try again", shared.ErrConflict)
		}
		return nil, err
	}
	// The new exclusions may close or reopen findings (effects.go).
	s.effects.Kick(tid)
	s.logger.Info("provider shared addresses moved out of scope", "tenant_id", tid.String(),
		"entries", res.Entries, "exclusions", res.Exclusions, "existing", res.Existing)
	return res, nil
}

// cloneTarget is a copy of t's state for the audit "before".
func cloneTarget(t *scopedom.Target) *scopedom.Target {
	c := *t
	return &c
}

// ProviderKeepInput keeps scanning one provider's listed entries.
type ProviderKeepInput struct {
	TenantID string
	Provider string
	Actor    Actor
}

// ProviderKeepResult is the entries kept.
type ProviderKeepResult struct {
	Provider string
	Kept     []ProviderEntry
}

// KeepProviderScanning records the organization's decision to keep scanning
// one provider's listed entries: they leave the card and are never held. It
// widens what the hold allows, so it needs a recent re-authentication (the
// route asks too).
func (s *Service) KeepProviderScanning(ctx context.Context, in ProviderKeepInput) (*ProviderKeepResult, error) {
	tid, err := shared.IDFromString(in.TenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	if s.providers == nil {
		return nil, ErrProviderAddressesUnavailable
	}
	if err := s.requireStepUp(ctx, in.Actor); err != nil {
		return nil, err
	}
	entries, err := s.providerEntriesOf(ctx, tid, in.Provider)
	if err != nil {
		return nil, err
	}
	res := &ProviderKeepResult{Provider: entries[0].r.Provider, Kept: make([]ProviderEntry, 0, len(entries))}
	keeps := make([]ProviderKeep, 0, len(entries))
	version := edgeaddr.Default().Version()
	for _, e := range entries {
		keeps = append(keeps, ProviderKeep{TargetID: e.t.ID(), Provider: res.Provider, DatasetVersion: version, DecidedBy: in.Actor.UserID})
		res.Kept = append(res.Kept, providerEntryOf(e.t))
	}
	if err := s.providers.SaveKeeps(ctx, tid, keeps); err != nil {
		return nil, err
	}
	s.logger.Info("provider shared addresses kept in scope", "tenant_id", tid.String(), "entries", len(keeps))
	return res, nil
}
