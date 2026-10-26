package easm

// Suggestion cards on the attack surface (research/117 option B): the only
// decisions about scope that still need a person, each grouped into one card
// instead of a row per asset.
//
//   - addresses_behind_names: addresses the organization's in-scope names
//     resolve to. A name never lends its address authority (an address is
//     not the organization's because a name points at it: dangling DNS,
//     shared hosting, a released cloud address), so a person decides. Shared
//     and CDN addresses are listed apart and never offered; an address whose
//     network we know nothing about is offered but marked unknown, never
//     presented as safe. While the organization's unclassified-scans mode
//     gives known, unshared addresses low-impact checks, only the unknown
//     ones wait; the others are listed apart as already checked.
//   - confirmed_out_of_scope: assets a person confirmed as the
//     organization's that no active scope entry covers (confirmations made
//     before a confirmation added its own entry).
//
// A card only offers: accepting it is an ordinary bulk add of exact scope
// entries (POST /scope/targets/bulk: scope write permission, step-up, the
// approval rules, audit). Nothing here writes. Every read is tenant-scoped
// and narrowed to the caller's data scope.

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"golang.org/x/net/publicsuffix"

	"github.com/openctemio/openctem/api/internal/app/datascope"
	"github.com/openctemio/openctem/api/internal/app/scope"
	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	"github.com/openctemio/openctem/api/pkg/domain/easmseed"
	"github.com/openctemio/openctem/api/pkg/domain/edgeaddr"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Suggestion card kinds.
const (
	CardAddressesBehindNames = "addresses_behind_names"
	CardConfirmedOutOfScope  = "confirmed_out_of_scope"
)

// Why an address is not offered.
const (
	SharedCDN          = "cdn"           // the address's own record says CDN
	SharedProvider     = "provider"      // its network belongs to a CDN or cloud provider
	SharedEdgeRange    = "edge_range"    // inside a published CDN edge range
	SharedManyDomains  = "many_domains"  // names of 3+ registrable domains resolve to it
	SharedOtherNetwork = "other_network" // its network is announced by another organization
)

// sharedDomainThreshold: an address names of this many registrable domains
// resolve to is shared hosting.
const sharedDomainThreshold = 3

// MaxSuggestionItems bounds the items of one card: accepting a card is one
// bulk add.
const MaxSuggestionItems = scope.MaxBulkTargets

// maxSuggestionScan bounds the rows a card reads.
const maxSuggestionScan = 2000

// SuggestionAddress is one address behind in-scope names.
type SuggestionAddress struct {
	AssetID string `json:"asset_id"`
	Address string `json:"address"`
	// ResolvedFrom: the caller's in-scope names that resolve to it (up to 10).
	ResolvedFrom []string `json:"resolved_from"`
	// Network: what we hold about its network; Known=false means nothing,
	// which is never read as "not shared".
	Network SuggestionNetwork `json:"network"`
	// Shared: why it is not offered (empty: offered).
	Shared string `json:"shared,omitempty"`
	// Ports: the open ports seen on the address or on the caller's names
	// that resolve to it (up to 20, ascending): what a port scan of the
	// address itself would look at again, and what scans of the names alone
	// can miss.
	Ports []int `json:"ports,omitempty"`
	// OtherNames: the caller's names resolving to it that no entry covers
	// (up to 10).
	OtherNames []string `json:"other_names,omitempty"`
	// Prefix: the organization's own announced prefix that holds the
	// address (from its network seeds), when the platform guardrails accept
	// it as a scope entry; offered as one rule in PrefixRules.
	Prefix string `json:"prefix,omitempty"`
}

// SuggestionPrefix is a network prefix of the organization's own (an
// announced prefix of a seeded AS) that holds offered addresses: adding it
// is one CIDR rule instead of an entry per address.
type SuggestionPrefix struct {
	Prefix    string `json:"prefix"`
	Addresses int    `json:"addresses"`
}

// SuggestionNetwork is what we hold about an address's network.
type SuggestionNetwork struct {
	Known    bool   `json:"known"`
	ASN      string `json:"asn,omitempty"`
	Org      string `json:"org,omitempty"`
	Provider string `json:"provider,omitempty"`
	// Class: edge, saas_hosting, cloud_shared or dedicated (the address
	// classifier, pkg/domain/edgeaddr). Only a dedicated address can be the
	// organization's.
	Class string `json:"class,omitempty"`
}

// SuggestionProvider is a provider whose addresses the in-scope names
// resolve to: none of them needs a decision.
type SuggestionProvider struct {
	Provider  string `json:"provider"`
	Class     string `json:"class"`
	Addresses int    `json:"addresses"`
}

// SuggestionAsset is one confirmed asset no entry covers.
type SuggestionAsset struct {
	AssetID    string `json:"asset_id"`
	Name       string `json:"name"`
	TargetType string `json:"target_type"`
}

// SuggestionCard is one decision.
type SuggestionCard struct {
	Kind string `json:"kind"`
	// Count: the items the card offers to add (Items).
	Count int `json:"count"`
	// Truncated: more items than one card carries; accepting adds these
	// and the card comes back with the rest.
	Truncated bool `json:"truncated"`
	// addresses_behind_names only.
	NamesCount          int `json:"names_count,omitempty"`
	UnknownNetworkCount int `json:"unknown_network_count,omitempty"`
	SharedCount         int `json:"shared_count,omitempty"`
	// CheckedCount: addresses that need no decision because the
	// organization's unclassified-scans mode already gives them low-impact
	// checks (a known network that is not shared); adding them is optional
	// (a full scan). Listed in CheckedAddresses, never in Addresses.
	CheckedCount int `json:"checked_count,omitempty"`
	// ProviderCount: the shared addresses that belong to a CDN, hosting or
	// cloud-shared provider (class not dedicated), grouped in Providers,
	// most addresses first; the rest of SharedCount is shared with other
	// organizations.
	ProviderCount    int                  `json:"provider_count,omitempty"`
	Providers        []SuggestionProvider `json:"providers,omitempty"`
	Addresses        []SuggestionAddress  `json:"addresses,omitempty"`
	SharedAddresses  []SuggestionAddress  `json:"shared_addresses,omitempty"`
	CheckedAddresses []SuggestionAddress  `json:"checked_addresses,omitempty"`
	// PrefixRules: the organization's own prefixes holding offered
	// addresses (Prefix), most addresses first.
	PrefixRules []SuggestionPrefix `json:"prefix_rules,omitempty"`
	// confirmed_out_of_scope only.
	Assets []SuggestionAsset `json:"assets,omitempty"`
}

// SuggestionCards is the answer.
type SuggestionCards struct {
	Cards []SuggestionCard `json:"cards"`
	// Total: the decisions waiting (the Review tab and sidebar badge): one
	// per card that offers something (Count > 0) plus NameRules. A card that
	// only lists addresses needing no decision (shared, already checked) is
	// returned for the page but never counted.
	Total int `json:"total"`
	// NameRules: the review-by-rule cards about names over the names that
	// wait for a decision (DecisionStates), as the Review tab lists them.
	NameRules int `json:"name_rules"`
	// CanAdd: the caller may accept a card (scope write permission).
	CanAdd bool `json:"can_add"`
}

// AddressBehindNames is one stored address and the names that resolve to it.
type AddressBehindNames struct {
	AssetID string
	Address string
	Props   map[string]any
	// AllNames: every name of the tenant resolving to it (shared check only,
	// never returned); VisibleNames: those in the caller's data scope.
	AllNames     []string
	VisibleNames []string
	// Ports: open ports recorded on the address asset or on its visible
	// names (asset_services), ascending.
	Ports []int
}

// SuggestionStore reads the cards' rows (*postgres.AttributionRepository).
type SuggestionStore interface {
	// AddressesBehindNames: the tenant's address assets in the caller's data
	// scope that names resolve to, not decided by a person as anything but
	// confirmed.
	AddressesBehindNames(ctx context.Context, tenantID shared.ID, scope *shared.DataScope, limit int) ([]AddressBehindNames, error)
	// ConfirmedByPerson: domain, subdomain and address assets a person
	// confirmed, in the caller's data scope, most recent first.
	ConfirmedByPerson(ctx context.Context, tenantID shared.ID, scope *shared.DataScope, limit int) ([]SuggestionAsset, error)
}

// SuggestionService builds the cards.
type SuggestionService struct {
	store     SuggestionStore
	coverage  ReviewCoverage
	dataScope *datascope.Enforcer
	orgName   OrgNamer
	seeded    SeededNetworks
	// guardrails decide which seeded prefixes may be offered as rules; nil
	// offers none.
	guardrails *scopedom.Guardrails
	// unclassified answers the organization's unclassified-scans mode; nil
	// or unreadable means off (every offered address waits).
	unclassified UnclassifiedPolicy
}

// DecisionStates are the attribution states that wait for a person: the
// Review tab lists them and the badge counts them. Discovered names are in
// the inventory already and need no decision.
var DecisionStates = []attribution.State{attribution.StateNeedsReview, attribution.StateCandidate}

// SetUnclassified lets the card tell addresses that already get low-impact
// checks (RFC-054 §16) from those that wait for a decision.
func (s *SuggestionService) SetUnclassified(p UnclassifiedPolicy) { s.unclassified = p }

// checksUnclassified: the organization's mode gives unclassified assets
// low-impact checks. Anything unreadable is off.
func (s *SuggestionService) checksUnclassified(ctx context.Context, tenantID shared.ID) bool {
	if s.unclassified == nil {
		return false
	}
	m, err := s.unclassified(ctx, tenantID)
	return err == nil && (m == unclassifiedLowImpact || m == unclassifiedFull)
}

// Finish sets NameRules and Total: one per card that offers something, plus
// the name rules.
func (c *SuggestionCards) Finish(nameRules int) {
	c.NameRules = nameRules
	c.Total = nameRules
	for _, card := range c.Cards {
		if card.Count > 0 {
			c.Total++
		}
	}
}

// SetGuardrails lets the card offer the organization's own prefixes as
// rules, each only when the platform guardrails accept it as an entry.
func (s *SuggestionService) SetGuardrails(g scopedom.Guardrails) { s.guardrails = &g }

// NewSuggestionService creates it. coverage is required (without it nothing
// can be told in or out of scope, so no card is built).
func NewSuggestionService(store SuggestionStore, coverage ReviewCoverage, scope *datascope.Enforcer, org OrgNamer, seeded SeededNetworks) *SuggestionService {
	return &SuggestionService{store: store, coverage: coverage, dataScope: scope, orgName: org, seeded: seeded}
}

// Cards returns the cards with something to decide, for the caller.
func (s *SuggestionService) Cards(ctx context.Context, tenantID shared.ID, canAdd bool) (*SuggestionCards, error) {
	out := &SuggestionCards{Cards: []SuggestionCard{}, CanAdd: canAdd}
	if s == nil || s.store == nil || s.coverage == nil {
		return out, nil
	}
	var view *shared.DataScope
	if s.dataScope != nil {
		sc, err := s.dataScope.Resolve(ctx, tenantID)
		if err != nil {
			return nil, fmt.Errorf("resolve data scope: %w", err)
		}
		view = sc
	}
	addrCard, err := s.addressCard(ctx, tenantID, view)
	if err != nil {
		return nil, err
	}
	if addrCard != nil {
		out.Cards = append(out.Cards, *addrCard)
	}
	confCard, err := s.confirmedCard(ctx, tenantID, view)
	if err != nil {
		return nil, err
	}
	if confCard != nil {
		out.Cards = append(out.Cards, *confCard)
	}
	return out, nil
}

func (s *SuggestionService) addressCard(ctx context.Context, tenantID shared.ID, view *shared.DataScope) (*SuggestionCard, error) {
	rows, err := s.store.AddressesBehindNames(ctx, tenantID, view, maxSuggestionScan)
	if err != nil {
		return nil, fmt.Errorf("addresses behind names: %w", err)
	}
	if len(rows) == 0 {
		return nil, nil
	}
	// Which names are in scope, and which addresses are already covered.
	ask := make([]string, 0, len(rows)*2)
	for _, r := range rows {
		ask = append(ask, r.Address)
		ask = append(ask, r.VisibleNames...)
	}
	cover, err := s.coverage.CoverOf(ctx, tenantID, ask)
	if err != nil {
		return nil, fmt.Errorf("suggestion coverage: %w", err)
	}
	org := ""
	if s.orgName != nil {
		if org, err = s.orgName(ctx, tenantID); err != nil {
			return nil, fmt.Errorf("organization name: %w", err)
		}
	}
	var seeds *easmseed.Networks
	if s.seeded != nil {
		n, err := s.seeded(ctx, tenantID)
		if err != nil {
			return nil, fmt.Errorf("network seeds: %w", err)
		}
		seeds = &n
	}
	checks := s.checksUnclassified(ctx, tenantID)
	card := &SuggestionCard{Kind: CardAddressesBehindNames, Addresses: []SuggestionAddress{},
		SharedAddresses: []SuggestionAddress{}, CheckedAddresses: []SuggestionAddress{}}
	names := map[string]bool{}
	providers := map[string]int{}
	for _, r := range rows {
		if _, covered := cover[r.Address]; covered {
			continue
		}
		var from []string
		for _, n := range r.VisibleNames {
			if _, ok := cover[n]; ok {
				from = append(from, n)
			}
		}
		if len(from) == 0 {
			continue // no in-scope name of the caller points at it
		}
		sort.Strings(from)
		all := from
		if len(from) > maxResolvedFrom {
			from = from[:maxResolvedFrom]
		}
		item := SuggestionAddress{AssetID: r.AssetID, Address: r.Address, ResolvedFrom: from}
		item.Network, item.Shared = classifyAddress(r, org, seeds)
		if item.Shared == "" {
			// A shared address's open ports are its provider's: never shown.
			item.Ports = addressPorts(r)
		}
		for _, n := range r.VisibleNames {
			if _, ok := cover[n]; !ok && len(item.OtherNames) < maxResolvedFrom {
				item.OtherNames = append(item.OtherNames, n)
			}
		}
		sort.Strings(item.OtherNames)
		if item.Shared == "" && seeds != nil {
			item.Prefix = s.ownPrefix(*seeds, r.Address)
		}
		if item.Shared != "" {
			card.SharedCount++
			if item.Network.Class != "" && item.Network.Class != string(edgeaddr.Dedicated) {
				card.ProviderCount++
				providers[item.Network.Provider+"|"+item.Network.Class]++
			}
			if len(card.SharedAddresses) < MaxSuggestionItems {
				card.SharedAddresses = append(card.SharedAddresses, item)
			}
			continue
		}
		if checks && item.Network.Known {
			// Already gets low-impact checks: no decision waits.
			card.CheckedCount++
			if len(card.CheckedAddresses) < MaxSuggestionItems {
				card.CheckedAddresses = append(card.CheckedAddresses, item)
			}
			continue
		}
		for _, n := range all {
			names[n] = true // names_count: the names behind the addresses that wait
		}
		if !item.Network.Known {
			card.UnknownNetworkCount++
		}
		if len(card.Addresses) < MaxSuggestionItems {
			card.Addresses = append(card.Addresses, item)
		} else {
			card.Truncated = true
		}
	}
	card.Count = len(card.Addresses)
	card.NamesCount = len(names)
	card.PrefixRules = prefixRules(card.Addresses)
	card.Providers = providerList(providers)

	if card.Count == 0 && card.SharedCount == 0 && card.CheckedCount == 0 {
		return nil, nil
	}
	return card, nil
}

// classifyAddress tells what we know about the address's network and why it
// is shared ("" when it is offered). The address classifier decides edge,
// hosting and cloud-shared space; the checks after it catch shared hosting
// it cannot know (many domains, another organization's network).
func classifyAddress(r AddressBehindNames, org string, seeds *easmseed.Networks) (SuggestionNetwork, string) {
	net := SuggestionNetwork{}
	var cdn string
	if r.Props != nil {
		net.ASN = strings.TrimSpace(asnHint(map[string]any{"asn": r.Props["asn"]}))
		net.Org, _ = r.Props["asn_org"].(string)
		net.Known = net.ASN != "" || net.Org != ""
		cdn, _ = r.Props["cdn"].(string)
	}
	res := edgeaddr.Default().Address(r.Address, cdn, net.Org)
	net.Class = string(res.Class)
	switch {
	case res.Basis == edgeaddr.BasisRange:
		net.Known, net.Provider = true, res.Provider
		return net, SharedEdgeRange
	case res.Basis == edgeaddr.BasisCDN:
		net.Known, net.Provider = true, res.Provider
		return net, SharedCDN
	case res.ProviderSpace():
		// Provider space, dedicated cloud addresses included: never offered
		// on a name's word alone.
		net.Provider = res.Provider
		return net, SharedProvider
	}
	if registrableDomains(r.AllNames) >= sharedDomainThreshold {
		return net, SharedManyDomains
	}
	if net.Org != "" && !orgMatches(org, net.Org) &&
		(seeds == nil || !seededNetwork(*seeds, r.Address, net.ASN, net.Org)) {
		return net, SharedOtherNetwork
	}
	return net, ""
}

// providerList is the providers by addresses, most first.
func providerList(m map[string]int) []SuggestionProvider {
	out := make([]SuggestionProvider, 0, len(m))
	for k, n := range m {
		provider, class, _ := strings.Cut(k, "|")
		out = append(out, SuggestionProvider{Provider: provider, Class: class, Addresses: n})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Addresses != out[j].Addresses {
			return out[i].Addresses > out[j].Addresses
		}
		return out[i].Provider < out[j].Provider
	})
	return out
}

// registrableDomains counts the distinct registrable domains among names.
func registrableDomains(names []string) int {
	seen := map[string]bool{}
	for _, n := range names {
		n = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(n)), ".")
		if n == "" {
			continue
		}
		reg, err := publicsuffix.EffectiveTLDPlusOne(n)
		if err != nil {
			reg = n
		}
		seen[reg] = true
	}
	return len(seen)
}

func (s *SuggestionService) confirmedCard(ctx context.Context, tenantID shared.ID, view *shared.DataScope) (*SuggestionCard, error) {
	rows, err := s.store.ConfirmedByPerson(ctx, tenantID, view, maxSuggestionScan)
	if err != nil {
		return nil, fmt.Errorf("confirmed assets: %w", err)
	}
	candidates := make([]SuggestionAsset, 0, len(rows))
	names := make([]string, 0, len(rows))
	for _, r := range rows {
		name := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(r.Name)), ".")
		if name == "" || strings.HasPrefix(name, "*.") || !scopedom.NeedsAuthority(name) {
			continue
		}
		r.Name = name
		candidates = append(candidates, r)
		names = append(names, name)
	}
	if len(candidates) == 0 {
		return nil, nil
	}
	cover, err := s.coverage.CoverOf(ctx, tenantID, names)
	if err != nil {
		return nil, fmt.Errorf("suggestion coverage: %w", err)
	}
	card := &SuggestionCard{Kind: CardConfirmedOutOfScope, Assets: []SuggestionAsset{}}
	seen := map[string]bool{}
	for _, c := range candidates {
		if _, ok := cover[c.Name]; ok || seen[c.Name] {
			continue
		}
		seen[c.Name] = true
		if len(card.Assets) >= MaxSuggestionItems {
			card.Truncated = true
			continue
		}
		card.Assets = append(card.Assets, c)
	}
	card.Count = len(card.Assets)
	if card.Count == 0 {
		return nil, nil
	}
	return card, nil
}

// SuggestionTargetType is the exact entry type of a stored asset type.
func SuggestionTargetType(assetType string) string {
	if assetType == "ip_address" {
		return string(scopedom.TargetTypeIPAddress)
	}
	return string(scopedom.TargetTypeDomain)
}

// edgeRangeProvider names the provider whose published edge range holds
// addr ("" when none does), from the address classifier's dataset. It is a
// floor, not a complete list: an address outside it with no network data is
// reported as unknown, never as not shared.
func edgeRangeProvider(addr string) string {
	if r := edgeaddr.Default().Address(addr, "", ""); r.Basis == edgeaddr.BasisRange {
		return r.Provider
	}
	return ""
}

// NameRuleCards counts the review-by-rule cards about names: one per
// suggested name rule, and one for the names no rule groups. Addresses are
// left out (the addresses card holds them).
func NameRuleCards(rs *RuleSuggestions) int {
	if rs == nil {
		return 0
	}
	n := 0
	for _, sg := range rs.Suggestions {
		if sg.Kind != "ip_cidr" {
			n++
		}
	}
	for _, it := range rs.Individual {
		if _, err := netip.ParseAddr(asset.HostOf(it.Name)); err != nil && !it.SharedIP {
			n++
			break
		}
	}
	return n
}

// maxCardPorts bounds the ports listed for one address.
const maxCardPorts = 20

// addressPorts merges the ports recorded in asset_services with the
// address's own "ports" property (open ones), ascending, at most
// maxCardPorts.
func addressPorts(r AddressBehindNames) []int {
	seen := map[int]bool{}
	for _, p := range r.Ports {
		if p > 0 && p <= 65535 {
			seen[p] = true
		}
	}
	if list, ok := r.Props["ports"].([]any); ok {
		for _, e := range list {
			m, ok := e.(map[string]any)
			if !ok {
				continue
			}
			if st, _ := m["state"].(string); st != "" && st != "open" {
				continue
			}
			if f, ok := m["port"].(float64); ok && f > 0 && f <= 65535 {
				seen[int(f)] = true
			}
		}
	}
	out := make([]int, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Ints(out)
	if len(out) > maxCardPorts {
		out = out[:maxCardPorts]
	}
	return out
}

// ownPrefix is the most specific announced prefix of the organization's
// seeded networks that holds addr and that the platform guardrails accept
// as a scope entry ("" when none does, or without guardrails).
func (s *SuggestionService) ownPrefix(n easmseed.Networks, addr string) string {
	if s.guardrails == nil {
		return ""
	}
	a, err := netip.ParseAddr(addr)
	if err != nil {
		return ""
	}
	a = a.Unmap()
	best := netip.Prefix{}
	for _, raw := range n.Prefixes {
		p, err := netip.ParsePrefix(raw)
		if err != nil || !p.Contains(a) || (best.IsValid() && p.Bits() <= best.Bits()) {
			continue
		}
		if s.guardrails.CheckPattern(scopedom.TargetTypeCIDR, p.Masked().String()) != nil {
			continue
		}
		best = p.Masked()
	}
	if !best.IsValid() {
		return ""
	}
	return best.String()
}

// prefixRules groups offered addresses by their own prefix, most addresses
// first.
func prefixRules(addrs []SuggestionAddress) []SuggestionPrefix {
	count := map[string]int{}
	for _, a := range addrs {
		if a.Prefix != "" {
			count[a.Prefix]++
		}
	}
	out := make([]SuggestionPrefix, 0, len(count))
	for p, n := range count {
		out = append(out, SuggestionPrefix{Prefix: p, Addresses: n})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Addresses != out[j].Addresses {
			return out[i].Addresses > out[j].Addresses
		}
		return out[i].Prefix < out[j].Prefix
	})
	return out
}
