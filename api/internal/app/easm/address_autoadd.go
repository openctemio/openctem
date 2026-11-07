package easm

// Addresses the organization's in-scope names resolve to are added to scope
// automatically when the evidence is strong (research/425, setting
// address_auto_add, default auto_strong). A name never makes an address the
// organization's (RFC-054 §4.3): strong evidence is the ownership band high
// (pkg/domain/addrowner), which needs an anchor the organization itself
// established (a network seed: its own AS and the prefixes that AS
// announces) plus more evidence and nothing holding it back (a brand-new
// address, names of other organizations on it). Shared, CDN, hosting and
// provider addresses are never added (the address classifier). With no
// network seed nothing is added: the default is safe on day one.
//
// Two or more strong addresses inside one prefix the organization's own AS
// announces become one entry for that prefix (the narrowest announced prefix
// the platform guardrails accept, never a computed supernet); the rest are
// exact address entries.
//
// Entries go through the scope service as an automatic actor: the
// organization's approval policy applies as to a person's add (an entry
// waits for its approvers when approvals are required), the guardrails, the
// deny list and the signer ledger apply per item, each entry is audited with
// its evidence and origin auto_address, and the administrators are told once
// per run. Under the Strict scan approval mode nothing is added. Each
// pattern is added at most once per tenant (AutoAddLog): removing the entry,
// or the prefix an address fell in, undoes it for good; an address a person
// rejected never reaches the card.

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/scope"
	"github.com/openctemio/openctem/api/pkg/domain/addrowner"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/scangov"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// SeededTenants lists the tenants with at least one AS network seed
// (*postgres.EASMNetworkSeedRepository): the only tenants an address can be
// strong for.
type SeededTenants interface {
	TenantsWithASNSeeds(ctx context.Context, limit int) ([]shared.ID, error)
}

// AutoAddLog remembers the patterns written for a tenant
// (*postgres.EASMAddressAutoAddRepository).
type AutoAddLog interface {
	Seen(ctx context.Context, tenantID shared.ID, patterns []string) (map[string]bool, error)
	Record(ctx context.Context, tenantID shared.ID, patterns []string) error
}

// maxAutoAddTenants bounds the tenants one run looks at.
const maxAutoAddTenants = 1000

// AddressAutoAdd adds the strong addresses behind in-scope names.
type AddressAutoAdd struct {
	cards    *SuggestionService
	targets  ConfirmScopeTargets
	settings ConfirmScopeSettings
	tenants  SeededTenants
	added    AutoAddLog
	notify   AdminNotifier
	audit    ScopeJoinAudit
	log      *logger.Logger
}

// NewAddressAutoAdd creates it. audit and notify may be nil; a nil other
// dependency adds nothing.
func NewAddressAutoAdd(cards *SuggestionService, targets ConfirmScopeTargets, settings ConfirmScopeSettings,
	tenants SeededTenants, added AutoAddLog, notify AdminNotifier, audit ScopeJoinAudit, log *logger.Logger) *AddressAutoAdd {
	if log == nil {
		log = logger.NewNop()
	}
	return &AddressAutoAdd{cards: cards, targets: targets, settings: settings, tenants: tenants, added: added,
		notify: notify, audit: audit, log: log}
}

func (a *AddressAutoAdd) ready() bool {
	return a != nil && a.cards != nil && a.targets != nil && a.settings != nil && a.tenants != nil && a.added != nil
}

// Run adds the strong addresses of every seeded tenant skip does not leave
// out and returns the entries added. One tenant's failure is logged and does
// not stop the rest.
func (a *AddressAutoAdd) Run(ctx context.Context, skip func(shared.ID) bool) (int, error) {
	if !a.ready() {
		return 0, nil
	}
	ids, err := a.tenants.TenantsWithASNSeeds(ctx, maxAutoAddTenants)
	if err != nil {
		return 0, fmt.Errorf("seeded tenants: %w", err)
	}
	total := 0
	for _, id := range ids {
		if ctx.Err() != nil {
			return total, ctx.Err()
		}
		if skip != nil && skip(id) {
			continue
		}
		n, err := a.RunTenant(ctx, id)
		if err != nil {
			a.log.Warn("address auto add failed", "tenant_id", id.String(), "error", logger.SanitizeError(err))
			continue
		}
		total += n
	}
	return total, nil
}

// AutoAddItem is one planned entry and why.
type AutoAddItem struct {
	Item scope.BulkTargetItem
	// Addresses: the strong addresses the entry covers.
	Addresses []SuggestionAddress
}

// PlanAutoAdd picks the entries for the strong addresses of a card: a prefix
// holding two or more of them, else the exact address. Exported for tests
// and for the card's explanation.
func PlanAutoAdd(card *SuggestionCard) []AutoAddItem {
	if card == nil {
		return nil
	}
	var strong []SuggestionAddress
	for _, list := range [][]SuggestionAddress{card.Addresses, card.CheckedAddresses} {
		for _, it := range list {
			if StrongAddress(it) {
				strong = append(strong, it)
			}
		}
	}
	byPrefix := map[string][]SuggestionAddress{}
	for _, it := range strong {
		if it.Prefix != "" {
			byPrefix[it.Prefix] = append(byPrefix[it.Prefix], it)
		}
	}
	var out []AutoAddItem
	inPrefix := map[string]bool{}
	prefixes := make([]string, 0, len(byPrefix))
	for p, list := range byPrefix {
		if len(list) >= 2 {
			prefixes = append(prefixes, p)
		}
	}
	sort.Strings(prefixes)
	for _, p := range prefixes {
		out = append(out, AutoAddItem{Item: scope.BulkTargetItem{TargetType: string(scopedom.TargetTypeCIDR), Pattern: p}, Addresses: byPrefix[p]})
		for _, it := range byPrefix[p] {
			inPrefix[it.Address] = true
		}
	}
	for _, it := range strong {
		if inPrefix[it.Address] {
			continue
		}
		out = append(out, AutoAddItem{Item: scope.BulkTargetItem{TargetType: string(scopedom.TargetTypeIPAddress), Pattern: it.Address}, Addresses: []SuggestionAddress{it}})
	}
	return out
}

// StrongAddress: an unshared address in the high ownership band.
func StrongAddress(it SuggestionAddress) bool {
	return it.Shared == "" && it.Ownership != nil && it.Ownership.Band == addrowner.High
}

// RunTenant adds one tenant's strong addresses and returns the entries
// added (pending ones included).
func (a *AddressAutoAdd) RunTenant(ctx context.Context, tenantID shared.ID) (int, error) {
	if !a.ready() {
		return 0, nil
	}
	mode, _ := a.targets.ApprovalPolicy(ctx, tenantID.String())
	ss, err := a.settings.GetScopeSettings(ctx, tenantID.String())
	if err != nil {
		return 0, fmt.Errorf("scope settings: %w", err)
	}
	if ss == nil || ss.AddressModeIn(mode.Normalized() == scangov.ModeStrict) != tenant.AddressAutoStrong {
		return 0, nil
	}
	// The system view: every address of the tenant, whoever looks later.
	card, err := a.cards.addressCard(ctx, tenantID, nil, maxSuggestionScan)
	if err != nil {
		return 0, err
	}
	plan, err := a.unseen(ctx, tenantID, PlanAutoAdd(card))
	if err != nil {
		return 0, err
	}
	if len(plan) == 0 {
		return 0, nil
	}
	if len(plan) > scope.MaxBulkTargets {
		plan = plan[:scope.MaxBulkTargets] // the rest on the next run
	}
	items := make([]scope.BulkTargetItem, 0, len(plan))
	for _, p := range plan {
		items = append(items, p.Item)
	}
	outcomes, err := a.targets.CreateTargets(ctx, scope.BulkTargetsInput{
		TenantID: tenantID.String(), Items: items,
		Reason: "Added automatically: your in-scope names resolve to it and your own network holds it",
		Actor:  scope.Actor{Automatic: true}, Origin: scopedom.OriginAutoAddress,
	})
	if err != nil {
		return 0, fmt.Errorf("add strong addresses to scope: %w", err)
	}
	added := make([]*scopedom.Target, 0, len(outcomes))
	var written []string
	for k, o := range outcomes {
		if k >= len(plan) {
			break
		}
		var dup *scopedom.DuplicateError
		switch {
		case o.Err == nil && o.Target != nil:
			added = append(added, o.Target)
			written = append(written, plan[k].Item.Pattern)
			a.auditAdded(ctx, tenantID, o.Target, plan[k])
		case errors.As(o.Err, &dup):
			// The entry exists already: remembered, so its later removal
			// by a person sticks.
			written = append(written, plan[k].Item.Pattern)
		}
	}
	if err := a.added.Record(ctx, tenantID, written); err != nil {
		return len(added), err
	}
	return len(added), nil
}

// unseen drops the items written before, and the addresses inside a prefix
// written before (its removal covers them too).
func (a *AddressAutoAdd) unseen(ctx context.Context, tenantID shared.ID, plan []AutoAddItem) ([]AutoAddItem, error) {
	if len(plan) == 0 {
		return nil, nil
	}
	ask := make([]string, 0, len(plan)*2)
	for _, p := range plan {
		ask = append(ask, p.Item.Pattern)
		for _, it := range p.Addresses {
			if it.Prefix != "" {
				ask = append(ask, it.Prefix)
			}
		}
	}
	seen, err := a.added.Seen(ctx, tenantID, ask)
	if err != nil {
		return nil, err
	}
	out := make([]AutoAddItem, 0, len(plan))
	for _, p := range plan {
		if seen[p.Item.Pattern] {
			continue
		}
		if len(p.Addresses) == 1 && p.Addresses[0].Prefix != "" && seen[p.Addresses[0].Prefix] {
			continue
		}
		out = append(out, p)
	}
	return out, nil
}

func (a *AddressAutoAdd) auditAdded(ctx context.Context, tenantID shared.ID, t *scopedom.Target, p AutoAddItem) {
	if a.audit == nil {
		return
	}
	var names, signals []string
	seenName, seenSig := map[string]bool{}, map[string]bool{}
	for _, it := range p.Addresses {
		for _, n := range it.ResolvedFrom {
			if !seenName[n] && len(names) < 10 {
				seenName[n] = true
				names = append(names, n)
			}
		}
		if it.Ownership != nil {
			for _, s := range it.Ownership.Signals {
				if !seenSig[s.ID] {
					seenSig[s.ID] = true
					signals = append(signals, s.ID)
				}
			}
		}
	}
	event := auditapp.NewSuccessEvent(auditdom.ActionScopeTargetCreated, auditdom.ResourceTypeScopeTarget, t.ID().String()).
		WithResourceName(t.Pattern()).
		WithMessage("Scope entry added automatically: in-scope names resolve to it and the organization's own network holds it").
		WithMetadata("origin", string(scopedom.OriginAutoAddress)).
		WithMetadata("status", string(t.Status())).
		WithMetadata("addresses", len(p.Addresses)).
		WithMetadata("resolved_from", strings.Join(names, ",")).
		WithMetadata("evidence", strings.Join(signals, ",")).
		WithMetadata("actor", "system")
	if err := a.audit.LogEvent(ctx, auditapp.AuditContext{TenantID: tenantID.String()}, event); err != nil {
		a.log.Warn("address auto add audit failed", "error", logger.SanitizeError(err))
	}
}
