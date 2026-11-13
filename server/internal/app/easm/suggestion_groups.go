package easm

// Groups on the addresses card (research/425 §5.3-5.5): one decision per
// network instead of one per address. Every address of the card is in
// exactly one group:
//
//   - own_prefix: inside a prefix the organization's own seeded network
//     announces and the platform guardrails accept as an entry; the group
//     offers that prefix as one entry (Range), never a computed supernet;
//   - own_network: in the organization's seeded network (AS, prefix or
//     organization name);
//   - network: a known network (AS and holder) that is not seeded: the group
//     asks "is this network yours?" (AskNetwork);
//   - block: no network data; grouped by /24 (IPv4) or /48 (IPv6) for
//     reading only (a block is never offered as an entry);
//   - other_network: shared because another organization announces it; the
//     group asks the network question too (a "yes" seeds it);
//   - declined: in a network the organization said is not its own
//     (DeclinedID undoes it);
//   - provider: a CDN, hosting or cloud provider's space, by provider;
//   - shared_hosting: names of three or more registrable domains resolve
//     to it.
//
// Groups only explain and bundle. What a decision may add or reject is
// checked again on the server against the caller's own card
// (address_decisions.go).

import (
	"net/netip"
	"sort"
	"strings"

	"github.com/openctemio/openctem/server/pkg/domain/easmseed"
	"github.com/openctemio/openctem/server/pkg/domain/edgeaddr"
)

// Group kinds.
const (
	GroupOwnPrefix     = "own_prefix"
	GroupOwnNetwork    = "own_network"
	GroupNetwork       = "network"
	GroupBlock         = "block"
	GroupOtherNetwork  = "other_network"
	GroupDeclined      = "declined"
	GroupProvider      = "provider"
	GroupSharedHosting = "shared_hosting"
)

// maxGroupNames bounds the names listed for one group.
const maxGroupNames = 10

// SuggestionGroup is a set of the card's addresses one decision covers.
type SuggestionGroup struct {
	// Key is stable for the same network: "<kind>:<network>".
	Key  string `json:"key"`
	Kind string `json:"kind" enums:"own_prefix,own_network,network,block,other_network,declined,provider,shared_hosting"`
	// Prefix: the own prefix (own_prefix) or the /24 or /48 (block).
	Prefix   string `json:"prefix,omitempty"`
	ASN      string `json:"asn,omitempty"`
	Org      string `json:"org,omitempty"`
	Provider string `json:"provider,omitempty"`
	// Addresses: the group's addresses on the card, waiting ones first.
	Addresses []string `json:"addresses"`
	// Waiting: addresses that wait for a decision (offered); Checked: those
	// already getting low-impact checks. A shared group has neither.
	Waiting int `json:"waiting"`
	Checked int `json:"checked"`
	// ResolvedFrom: in-scope names behind the group's addresses (up to 10).
	ResolvedFrom []string `json:"resolved_from"`
	// Evidence: ownership signals and how many of the addresses carry each.
	Evidence []GroupEvidence `json:"evidence,omitempty"`
	// Range: one entry that covers the group (own_prefix only).
	Range string `json:"range,omitempty"`
	// AskNetwork: the group may be answered "is this network yours?".
	AskNetwork bool `json:"ask_network,omitempty"`
	// Shared: no bulk add; an address may only be added on its own.
	Shared bool `json:"shared,omitempty"`
	// DeclinedID: the organization's "not ours" answer (declined only).
	DeclinedID string `json:"declined_id,omitempty"`
}

// GroupEvidence is one ownership signal over a group.
type GroupEvidence struct {
	ID    string `json:"id"`
	Kind  string `json:"kind"`
	Count int    `json:"count"`
}

type groupBuild struct {
	g       *SuggestionGroup
	names   map[string]bool
	signals map[string]*GroupEvidence
}

// groupAddresses builds the card's groups.
func groupAddresses(card *SuggestionCard, seeds *easmseed.Networks, declined []easmseed.Declined) []SuggestionGroup {
	builds := map[string]*groupBuild{}
	add := func(it SuggestionAddress, waiting, checked bool) {
		g := groupOf(it, seeds, declined)
		b := builds[g.Key]
		if b == nil {
			b = &groupBuild{g: &g, names: map[string]bool{}, signals: map[string]*GroupEvidence{}}
			builds[g.Key] = b
		}
		b.g.Addresses = append(b.g.Addresses, it.Address)
		switch {
		case waiting:
			b.g.Waiting++
		case checked:
			b.g.Checked++
		}
		for _, n := range it.ResolvedFrom {
			if !b.names[n] && len(b.names) < maxGroupNames {
				b.names[n] = true
				b.g.ResolvedFrom = append(b.g.ResolvedFrom, n)
			}
		}
		if it.Ownership != nil {
			for _, s := range it.Ownership.Signals {
				e := b.signals[s.ID]
				if e == nil {
					e = &GroupEvidence{ID: s.ID, Kind: string(s.Kind)}
					b.signals[s.ID] = e
				}
				e.Count++
			}
		}
	}
	for _, it := range card.Addresses {
		add(it, true, false)
	}
	for _, it := range card.CheckedAddresses {
		add(it, false, true)
	}
	for _, it := range card.SharedAddresses {
		add(it, false, false)
	}
	out := make([]SuggestionGroup, 0, len(builds))
	for _, b := range builds {
		for _, e := range b.signals {
			b.g.Evidence = append(b.g.Evidence, *e)
		}
		sort.Slice(b.g.Evidence, func(i, j int) bool {
			if b.g.Evidence[i].Count != b.g.Evidence[j].Count {
				return b.g.Evidence[i].Count > b.g.Evidence[j].Count
			}
			return b.g.Evidence[i].ID < b.g.Evidence[j].ID
		})
		sort.Strings(b.g.ResolvedFrom)
		if b.g.ResolvedFrom == nil {
			b.g.ResolvedFrom = []string{}
		}
		out = append(out, *b.g)
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if ka, kb := groupKindRank(a.Kind), groupKindRank(b.Kind); ka != kb {
			return ka < kb
		}
		if a.Waiting != b.Waiting {
			return a.Waiting > b.Waiting
		}
		if len(a.Addresses) != len(b.Addresses) {
			return len(a.Addresses) > len(b.Addresses)
		}
		return a.Key < b.Key
	})
	return out
}

func groupKindRank(kind string) int {
	switch kind {
	case GroupOwnPrefix:
		return 0
	case GroupOwnNetwork:
		return 1
	case GroupNetwork:
		return 2
	case GroupBlock:
		return 3
	case GroupOtherNetwork:
		return 4
	case GroupDeclined:
		return 5
	case GroupProvider:
		return 6
	}
	return 7
}

// groupOf is the group one address belongs to (without its counts).
func groupOf(it SuggestionAddress, seeds *easmseed.Networks, declined []easmseed.Declined) SuggestionGroup {
	n := it.Network
	g := SuggestionGroup{ASN: n.ASN, Org: n.Org, Addresses: []string{}}
	netKey := networkKey(n)
	switch {
	case it.Shared == SharedDeclined:
		g.Kind, g.Shared, g.DeclinedID = GroupDeclined, true, declinedNetwork(declined, n)
		g.Key = GroupDeclined + ":" + netKey
	case it.Shared == SharedOtherNetwork:
		g.Kind, g.Shared, g.AskNetwork = GroupOtherNetwork, true, netKey != ""
		g.Key = GroupOtherNetwork + ":" + netKey
	case it.Shared == SharedManyDomains:
		g.Kind, g.Shared = GroupSharedHosting, true
		g.Key = GroupSharedHosting
	case it.Shared != "":
		g.Kind, g.Shared, g.Provider = GroupProvider, true, n.Provider
		cls := n.Class
		if cls == "" {
			cls = string(edgeaddr.Dedicated)
		}
		g.Key = GroupProvider + ":" + strings.ToLower(n.Provider) + "|" + cls
	case it.Prefix != "":
		g.Kind, g.Prefix, g.Range = GroupOwnPrefix, it.Prefix, it.Prefix
		g.Key = GroupOwnPrefix + ":" + it.Prefix
	case netKey != "" && seeds != nil && seededNetwork(*seeds, it.Address, n.ASN, n.Org):
		g.Kind = GroupOwnNetwork
		g.Key = GroupOwnNetwork + ":" + netKey
	case netKey != "":
		g.Kind, g.AskNetwork = GroupNetwork, true
		g.Key = GroupNetwork + ":" + netKey
	default:
		g.Kind, g.Prefix = GroupBlock, addressBlock(it.Address)
		g.Key = GroupBlock + ":" + g.Prefix
	}
	return g
}

// networkKey names an address's network: its AS, else its holder's name
// (lower-case), else "".
func networkKey(n SuggestionNetwork) string {
	if a := strings.ToUpper(strings.TrimSpace(n.ASN)); a != "" {
		return a
	}
	return strings.ToLower(strings.Join(strings.Fields(n.Org), " "))
}

// addressBlock is the /24 (IPv4) or /48 (IPv6) holding addr, for display.
func addressBlock(addr string) string {
	a, err := netip.ParseAddr(addr)
	if err != nil {
		return addr
	}
	a = a.Unmap()
	bits := 48
	if a.Is4() {
		bits = 24
	}
	p, err := a.Prefix(bits)
	if err != nil {
		return addr
	}
	return p.String()
}

// declinedNetwork is the id of the organization's "not ours" answer that
// holds the network ("" when none does): the same AS, or the same holder
// name when the network has no AS.
func declinedNetwork(declined []easmseed.Declined, n SuggestionNetwork) string {
	asn := strings.ToUpper(strings.TrimSpace(n.ASN))
	org := strings.ToLower(strings.Join(strings.Fields(n.Org), " "))
	for _, d := range declined {
		switch d.Kind {
		case easmseed.KindASN:
			if asn != "" && strings.EqualFold(d.Value, asn) {
				return d.ID
			}
		case easmseed.KindOrgName:
			if asn == "" && org != "" && strings.EqualFold(strings.Join(strings.Fields(d.Value), " "), org) {
				return d.ID
			}
		}
	}
	return ""
}
