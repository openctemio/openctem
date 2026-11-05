package easm

// Bulk decisions on the addresses card (research/425 §5.4-5.5): add many
// addresses (or the organization's own prefix holding them) in one step,
// mark many as not the organization's, and answer "is this network yours?".
//
// Threat model. The caller is a person of the tenant with the route's
// permission; the request body is untrusted. Nothing posted is taken on its
// word: every address and range must be on the caller's own card, rebuilt
// here for the tenant from the authenticated context and narrowed to the
// caller's data scope (an address of another tenant, one outside the
// caller's data scope, one a scope entry already covers or one nobody's
// in-scope name resolves to is refused, and the whole request with it). A
// shared, CDN or provider address is never part of a bulk add: only one at a
// time, explicitly (include_shared). A range is only the organization's own
// prefix the card offers, inside the platform guardrails, never a computed
// one. Additions go through the scope service as the person (guardrails,
// deny list, step-up, the approval policy, the signer ledger, audit per
// entry); rejections through the review service (data scope, audit); a
// network answer is a network seed (yes) or a declined network (no), both
// tenant rows. Every answer is reversible: remove the entry, undo the
// rejection, remove the seed or the declined network.

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/openctemio/openctem/api/internal/app/scope"
	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	"github.com/openctemio/openctem/api/pkg/domain/easmseed"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// Refusals of a whole decision.
var (
	ErrDecisionEmpty      = shared.NewDomainError("DECISION_EMPTY", "Choose at least one address", shared.ErrValidation)
	ErrDecisionTooMany    = shared.NewDomainError("DECISION_TOO_MANY", fmt.Sprintf("Decide at most %d addresses at once", scope.MaxBulkTargets), shared.ErrValidation)
	ErrDecisionNotPending = shared.NewDomainError("DECISION_NOT_PENDING", "Some of these addresses or ranges no longer wait for a decision: reload the card", shared.ErrValidation)
	ErrDecisionShared     = shared.NewDomainError("DECISION_SHARED", "A shared or provider address can only be added on its own", shared.ErrValidation)
	ErrNetworkNotAsked    = shared.NewDomainError("NETWORK_NOT_ASKED", "This network is not waiting for an answer: reload the card", shared.ErrValidation)
)

// AddressDecisionReview rejects assets (*ReviewService).
type AddressDecisionReview interface {
	DecideAs(ctx context.Context, tenantID shared.ID, assetIDs []string, state attribution.State, actor ScopeActor) (*DecisionResult, error)
}

// AddressDecisionSeeds adds network seeds (*NetworkSeedService).
type AddressDecisionSeeds interface {
	Create(ctx context.Context, tenantID shared.ID, actor *shared.ID, kind easmseed.Kind, value, label string) (*SeedView, error)
}

// DeclinedNetworkStore stores the organization's "not ours" network answers
// (*postgres.EASMDeclinedNetworkRepository). Every method is tenant-scoped.
type DeclinedNetworkStore interface {
	DeclinedNetworks
	Decline(ctx context.Context, tenantID shared.ID, kind easmseed.Kind, value, label string, by *shared.ID) (*easmseed.Declined, error)
	Undecline(ctx context.Context, tenantID shared.ID, id string) (*easmseed.Declined, error)
	UndeclineValue(ctx context.Context, tenantID shared.ID, kind easmseed.Kind, value string) error
}

// AddressDecisions applies the bulk decisions.
type AddressDecisions struct {
	cards    *SuggestionService
	targets  ConfirmScopeTargets
	review   AddressDecisionReview
	seeds    AddressDecisionSeeds
	declined DeclinedNetworkStore
	// autoAdd adds the addresses a "yes" made strong at once; nil leaves
	// them to the next controller run.
	autoAdd *AddressAutoAdd
}

// NewAddressDecisions creates it; a nil dependency refuses what needs it.
func NewAddressDecisions(cards *SuggestionService, targets ConfirmScopeTargets, review AddressDecisionReview,
	seeds AddressDecisionSeeds, declined DeclinedNetworkStore, autoAdd *AddressAutoAdd) *AddressDecisions {
	return &AddressDecisions{cards: cards, targets: targets, review: review, seeds: seeds, declined: declined, autoAdd: autoAdd}
}

// errDecisionsUnavailable: a dependency is not wired.
var errDecisionsUnavailable = errors.New("address decisions are not configured")

// AddressAddInput is a bulk add from the card.
type AddressAddInput struct {
	Addresses []string
	// Ranges: the organization's own prefixes the card offers.
	Ranges []string
	// IncludeShared allows one shared address, alone ("add anyway").
	IncludeShared bool
}

// What happened to one entry of a bulk add.
const (
	AddressResultCreated = "created"
	AddressResultExists  = "exists"
	AddressResultRefused = "refused"
)

// AddressAddItem is what happened to one entry.
type AddressAddItem struct {
	TargetType string `json:"target_type"`
	Pattern    string `json:"pattern"`
	Result     string `json:"result" enums:"created,exists,refused"`
	ID         string `json:"id,omitempty"`
	Status     string `json:"status,omitempty"`
	Code       string `json:"code,omitempty"`
	Message    string `json:"message,omitempty"`
}

// AddressAddResult is the answer to a bulk add.
type AddressAddResult struct {
	Items    []AddressAddItem `json:"items"`
	Created  int              `json:"created"`
	Pending  int              `json:"pending"`
	Existing int              `json:"existing"`
	Refused  int              `json:"refused"`
	// Names: the in-scope names behind the added addresses (up to 10).
	Names []string `json:"names"`
}

// callerCard is the addresses card as the caller sees it.
func (d *AddressDecisions) callerCard(ctx context.Context, tenantID shared.ID) (*SuggestionCard, error) {
	s := d.cards
	if s == nil || s.store == nil || s.coverage == nil {
		return nil, errDecisionsUnavailable
	}
	var view *shared.DataScope
	if s.dataScope != nil {
		sc, err := s.dataScope.Resolve(ctx, tenantID)
		if err != nil {
			return nil, fmt.Errorf("resolve data scope: %w", err)
		}
		view = sc
	}
	if s.addressModeOf(ctx, tenantID) == tenant.AddressNever {
		return &SuggestionCard{}, nil
	}
	card, err := s.addressCard(ctx, tenantID, view)
	if err != nil {
		return nil, err
	}
	if card == nil {
		card = &SuggestionCard{}
	}
	return card, nil
}

type cardIndex struct {
	offered map[string]SuggestionAddress // waiting and already checked
	shared  map[string]SuggestionAddress
	ranges  map[string]bool
}

func indexCard(card *SuggestionCard) cardIndex {
	ix := cardIndex{offered: map[string]SuggestionAddress{}, shared: map[string]SuggestionAddress{}, ranges: map[string]bool{}}
	for _, list := range [][]SuggestionAddress{card.Addresses, card.CheckedAddresses} {
		for _, a := range list {
			ix.offered[a.Address] = a
		}
	}
	for _, a := range card.SharedAddresses {
		ix.shared[a.Address] = a
	}
	for _, g := range card.Groups {
		if g.Range != "" {
			ix.ranges[g.Range] = true
		}
	}
	return ix
}

// canonicalAddress is the address as the card writes it ("" when it is not one).
func canonicalAddress(s string) string {
	a, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return ""
	}
	return a.Unmap().String()
}

func canonicalPrefix(s string) string {
	p, err := netip.ParsePrefix(strings.TrimSpace(s))
	if err != nil {
		return ""
	}
	return p.Masked().String()
}

// planAdd validates a bulk add against the caller's card and returns the
// entries and the addresses they cover.
func (d *AddressDecisions) planAdd(card *SuggestionCard, in AddressAddInput) ([]scope.BulkTargetItem, []SuggestionAddress, error) {
	addrs := dedupe(in.Addresses, canonicalAddress)
	ranges := dedupe(in.Ranges, canonicalPrefix)
	switch {
	case len(addrs) == 0 && len(ranges) == 0:
		return nil, nil, ErrDecisionEmpty
	case len(addrs)+len(ranges) > scope.MaxBulkTargets:
		return nil, nil, ErrDecisionTooMany
	}
	if len(addrs) != len(nonEmpty(in.Addresses)) || len(ranges) != len(nonEmpty(in.Ranges)) {
		return nil, nil, ErrDecisionNotPending // a value that is not an address or prefix
	}
	ix := indexCard(card)
	var covered []SuggestionAddress
	items := make([]scope.BulkTargetItem, 0, len(addrs)+len(ranges))
	prefixes := make([]netip.Prefix, 0, len(ranges))
	for _, r := range ranges {
		if !ix.ranges[r] {
			return nil, nil, ErrDecisionNotPending
		}
		if g := d.cards.guardrails; g != nil && g.CheckPattern(scopedom.TargetTypeCIDR, r) != nil {
			return nil, nil, ErrDecisionNotPending
		}
		prefixes = append(prefixes, netip.MustParsePrefix(r))
		items = append(items, scope.BulkTargetItem{TargetType: string(scopedom.TargetTypeCIDR), Pattern: r})
	}
	for _, a := range addrs {
		item, ok := ix.offered[a]
		if !ok {
			sh, isShared := ix.shared[a]
			if !isShared {
				return nil, nil, ErrDecisionNotPending
			}
			if !in.IncludeShared || len(addrs) != 1 || len(ranges) != 0 {
				return nil, nil, ErrDecisionShared
			}
			item = sh
		}
		covered = append(covered, item)
		ip := netip.MustParseAddr(a)
		inRange := false
		for _, p := range prefixes {
			if p.Contains(ip) {
				inRange = true
				break
			}
		}
		if !inRange {
			items = append(items, scope.BulkTargetItem{TargetType: string(scopedom.TargetTypeIPAddress), Pattern: a})
		}
	}
	// The addresses a range covers count as decided too.
	for _, p := range prefixes {
		for a, item := range ix.offered {
			if ip, err := netip.ParseAddr(a); err == nil && p.Contains(ip) && !containsAddr(covered, a) {
				covered = append(covered, item)
			}
		}
	}
	return items, covered, nil
}

// Add adds addresses and ranges of the caller's card to scope as the person.
func (d *AddressDecisions) Add(ctx context.Context, tenantID shared.ID, actor ScopeActor, in AddressAddInput) (*AddressAddResult, error) {
	if d == nil || d.targets == nil {
		return nil, errDecisionsUnavailable
	}
	card, err := d.callerCard(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	items, covered, err := d.planAdd(card, in)
	if err != nil {
		return nil, err
	}
	names := namesOf(covered, maxGroupNames)
	reason := "Decisions: addresses your in-scope names resolve to"
	if len(names) > 0 {
		reason += " (" + strings.Join(names[:min(len(names), 5)], ", ") + ")"
	}
	outcomes, err := d.targets.CreateTargets(ctx, scope.BulkTargetsInput{
		TenantID: tenantID.String(), Items: items, Reason: reason,
		CreatedBy: actor.UserID, Actor: actor.Actor, Origin: scopedom.OriginConfirmed,
	})
	if err != nil {
		return nil, err
	}
	res := &AddressAddResult{Items: make([]AddressAddItem, 0, len(outcomes)), Names: names}
	for _, o := range outcomes {
		it := AddressAddItem{TargetType: o.Item.TargetType, Pattern: o.Item.Pattern}
		var dup *scopedom.DuplicateError
		var de *shared.DomainError
		switch {
		case o.Err == nil && o.Target != nil:
			it.Result, it.ID, it.Status = AddressResultCreated, o.Target.ID().String(), o.Target.Status().String()
			res.Created++
			if !o.Target.IsActive() {
				res.Pending++
			}
		case errors.As(o.Err, &dup):
			it.Result, it.ID, it.Status = AddressResultExists, dup.Existing.ID.String(), dup.Existing.Status.String()
			res.Existing++
		default:
			it.Result = AddressResultRefused
			if errors.As(o.Err, &de) {
				it.Code, it.Message = de.Code, de.Message
			}
			res.Refused++
		}
		res.Items = append(res.Items, it)
	}
	return res, nil
}

// AddressRejectResult is the answer to "not ours".
type AddressRejectResult struct {
	// AssetIDs: the address assets marked rejected (for Undo).
	AssetIDs  []string `json:"asset_ids"`
	Addresses []string `json:"addresses"`
}

// Reject marks addresses of the caller's card as not the organization's.
func (d *AddressDecisions) Reject(ctx context.Context, tenantID shared.ID, actor ScopeActor, addresses []string) (*AddressRejectResult, error) {
	if d == nil || d.review == nil {
		return nil, errDecisionsUnavailable
	}
	addrs := dedupe(addresses, canonicalAddress)
	switch {
	case len(addrs) == 0:
		return nil, ErrDecisionEmpty
	case len(addrs) > scope.MaxBulkTargets:
		return nil, ErrDecisionTooMany
	case len(addrs) != len(nonEmpty(addresses)):
		return nil, ErrDecisionNotPending
	}
	card, err := d.callerCard(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	ix := indexCard(card)
	items := make([]SuggestionAddress, 0, len(addrs))
	for _, a := range addrs {
		it, ok := ix.offered[a]
		if !ok {
			if it, ok = ix.shared[a]; !ok {
				return nil, ErrDecisionNotPending
			}
		}
		items = append(items, it)
	}
	return d.reject(ctx, tenantID, actor, items)
}

func (d *AddressDecisions) reject(ctx context.Context, tenantID shared.ID, actor ScopeActor, items []SuggestionAddress) (*AddressRejectResult, error) {
	out := &AddressRejectResult{AssetIDs: []string{}, Addresses: []string{}}
	if len(items) == 0 {
		return out, nil
	}
	ids := make([]string, 0, len(items))
	for _, it := range items {
		ids = append(ids, it.AssetID)
	}
	res, err := d.review.DecideAs(ctx, tenantID, ids, attribution.StateRejected, actor)
	if err != nil {
		return nil, err
	}
	byID := map[string]string{}
	for _, it := range items {
		byID[it.AssetID] = it.Address
	}
	for _, dd := range res.Decided {
		out.AssetIDs = append(out.AssetIDs, dd.AssetID)
		out.Addresses = append(out.Addresses, byID[dd.AssetID])
	}
	return out, nil
}

// NetworkAnswerResult is the answer to "is this network yours?".
type NetworkAnswerResult struct {
	Kind  string `json:"kind" enums:"asn,org_name"`
	Value string `json:"value"`
	// SeedID: the network seed a "yes" added (remove it to undo).
	SeedID string `json:"seed_id,omitempty"`
	// AutoAdded: entries the address setting added at once (pending ones
	// included); the others stay on the card with their evidence.
	AutoAdded int `json:"auto_added"`
	// DeclinedID: the declined network a "no" recorded (remove it to undo).
	DeclinedID string `json:"declined_id,omitempty"`
	// Rejected: the addresses a "no" marked not the organization's.
	Rejected *AddressRejectResult `json:"rejected,omitempty"`
}

// askedGroup finds the card's group with the key that asks the network
// question.
func askedGroup(card *SuggestionCard, key string) (SuggestionGroup, easmseed.Kind, string, error) {
	for _, g := range card.Groups {
		if g.Key != key || !g.AskNetwork {
			continue
		}
		if g.ASN != "" {
			v, err := easmseed.NormalizeASN(g.ASN)
			if err != nil {
				return g, "", "", fmt.Errorf("%w: the network of this group is not valid", shared.ErrValidation)
			}
			return g, easmseed.KindASN, v, nil
		}
		v, err := easmseed.NormalizeOrgName(g.Org)
		if err != nil {
			return g, "", "", fmt.Errorf("%w: the network of this group is not valid", shared.ErrValidation)
		}
		return g, easmseed.KindOrgName, v, nil
	}
	return SuggestionGroup{}, "", "", ErrNetworkNotAsked
}

// NetworkIsOurs records the group's network as the organization's own (a
// network seed); with the address setting on, the addresses that makes
// strong are added at once, through the approval policy.
func (d *AddressDecisions) NetworkIsOurs(ctx context.Context, tenantID shared.ID, actor ScopeActor, key string) (*NetworkAnswerResult, error) {
	if d == nil || d.seeds == nil {
		return nil, errDecisionsUnavailable
	}
	card, err := d.callerCard(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	g, kind, value, err := askedGroup(card, key)
	if err != nil {
		return nil, err
	}
	var by *shared.ID
	if id, err := shared.IDFromString(actor.UserID); err == nil {
		by = &id
	}
	sd, err := d.seeds.Create(ctx, tenantID, by, kind, value, g.Org)
	if err != nil {
		return nil, err
	}
	if d.declined != nil {
		if err := d.declined.UndeclineValue(ctx, tenantID, kind, value); err != nil {
			return nil, err
		}
	}
	out := &NetworkAnswerResult{Kind: string(kind), Value: value, SeedID: sd.ID}
	if d.autoAdd != nil {
		n, err := d.autoAdd.RunTenant(ctx, tenantID)
		if err != nil {
			// The seed stands; the next controller run adds them.
			n = 0
		}
		out.AutoAdded = n
	}
	return out, nil
}

// NetworkNotOurs records the group's network as not the organization's and
// marks the group's addresses rejected; the question is not asked again.
func (d *AddressDecisions) NetworkNotOurs(ctx context.Context, tenantID shared.ID, actor ScopeActor, key string) (*NetworkAnswerResult, error) {
	if d == nil || d.declined == nil || d.review == nil {
		return nil, errDecisionsUnavailable
	}
	card, err := d.callerCard(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	g, kind, value, err := askedGroup(card, key)
	if err != nil {
		return nil, err
	}
	var by *shared.ID
	if id, err := shared.IDFromString(actor.UserID); err == nil {
		by = &id
	}
	dec, err := d.declined.Decline(ctx, tenantID, kind, value, g.Org, by)
	if err != nil {
		return nil, err
	}
	ix := indexCard(card)
	items := make([]SuggestionAddress, 0, len(g.Addresses))
	for _, a := range g.Addresses {
		if it, ok := ix.offered[a]; ok {
			items = append(items, it)
		} else if it, ok := ix.shared[a]; ok {
			items = append(items, it)
		}
	}
	rej, err := d.reject(ctx, tenantID, actor, items)
	if err != nil {
		return nil, err
	}
	return &NetworkAnswerResult{Kind: string(kind), Value: value, DeclinedID: dec.ID, Rejected: rej}, nil
}

// Undecline removes a "not ours" network answer of the tenant.
func (d *AddressDecisions) Undecline(ctx context.Context, tenantID shared.ID, id string) (*easmseed.Declined, error) {
	if d == nil || d.declined == nil {
		return nil, errDecisionsUnavailable
	}
	return d.declined.Undecline(ctx, tenantID, id)
}

func dedupe(in []string, canon func(string) string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, v := range in {
		c := canon(v)
		if c == "" || seen[c] {
			continue
		}
		seen[c] = true
		out = append(out, c)
	}
	return out
}

// nonEmpty is the distinct non-blank values as given (for telling junk from
// duplicates).
func nonEmpty(in []string) []string {
	return dedupe(in, func(s string) string {
		if c := canonicalAddress(s); c != "" {
			return c
		}
		if c := canonicalPrefix(s); c != "" {
			return c
		}
		return strings.TrimSpace(s)
	})
}

func containsAddr(list []SuggestionAddress, a string) bool {
	for _, it := range list {
		if it.Address == a {
			return true
		}
	}
	return false
}

func namesOf(items []SuggestionAddress, limit int) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, it := range items {
		for _, n := range it.ResolvedFrom {
			if !seen[n] {
				seen[n] = true
				out = append(out, n)
			}
		}
	}
	sort.Strings(out)
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}
