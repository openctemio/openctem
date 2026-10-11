package easm

// Address suggestions (RFC-054 §14.7, R4): the public addresses the
// organization's in-scope names resolve to, offered for one click into scope
// instead of being inherited. A name grant never becomes an address grant on
// its own (a dangling record can point at someone else's address); a person
// sees each address with the names it came from and adds it through the
// scope service. Addresses that look shared are left out: an edge or CDN
// provider's address, and an address names of three or more registrable
// domains resolve to (shared hosting). Every read is tenant-scoped and the
// list is narrowed to the caller's data scope (the address and the names).

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/net/publicsuffix"

	"github.com/openctemio/openctem/api/internal/app/datascope"
	"github.com/openctemio/openctem/api/internal/app/scopeauth"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ResolvedName is a name that resolves to an address.
type ResolvedName struct {
	AssetID string
	Name    string
}

// ResolvedAddress is an IP address asset with the names resolving to it.
type ResolvedAddress struct {
	AssetID    string
	Address    string
	Properties map[string]any
	Names      []ResolvedName
}

// ResolvedAddressStore reads resolution edges (*postgres.ScopeAddressRepository).
type ResolvedAddressStore interface {
	ResolvedAddresses(ctx context.Context, tenantID shared.ID, limit int) ([]ResolvedAddress, error)
}

// AddressSuggestion is one address to offer.
type AddressSuggestion struct {
	Address string `json:"address"`
	AssetID string `json:"asset_id"`
	// Names are the caller-visible in-scope names that resolve to it.
	Names []string `json:"names"`
	// Provider names a cloud provider that owns the address space, so the
	// person sees it before adding (empty when unknown).
	Provider string `json:"provider,omitempty"`
}

// AddressSuggestions is the list and what was left out.
type AddressSuggestions struct {
	Data []AddressSuggestion `json:"data"`
	// SkippedShared counts addresses left out as shared (edge/CDN provider,
	// or names of three or more registrable domains resolve to them).
	SkippedShared int `json:"skipped_shared"`
}

// maxResolvedAddresses bounds one suggestion read.
const maxResolvedAddresses = 2000

// sharedHostingDomains is how many registrable domains resolving to one
// address make it shared hosting.
const sharedHostingDomains = 3

// edgeProviders own address space many organizations share in front of
// their sites: such an address is never offered.
var edgeProviders = []string{
	"cloudflare", "akamai", "fastly", "incapsula", "imperva", "sucuri", "stackpath", "edgecast",
	"limelight", "bunny", "vercel", "netlify", "github", "heroku", "cloudfront",
}

// cloudProviders own address space that is often a tenant's own instance:
// offered, with the provider named.
var cloudProviders = []string{
	"amazon", "aws", "google", "microsoft", "azure", "digitalocean", "linode", "akamai connected",
	"ovh", "hetzner", "alibaba", "tencent", "oracle", "vultr", "scaleway",
}

// AddressSuggester builds the suggestions with the active gate's scope
// authority and platform guardrails.
type AddressSuggester struct {
	store     ResolvedAddressStore
	gate      *ActiveGate
	dataScope *datascope.Enforcer
}

// NewAddressSuggester creates the suggester. A nil enforcer means
// unrestricted (internal callers only).
func NewAddressSuggester(store ResolvedAddressStore, gate *ActiveGate, enforcer *datascope.Enforcer) *AddressSuggester {
	return &AddressSuggester{store: store, gate: gate, dataScope: enforcer}
}

// Suggest lists the addresses to offer for the caller.
func (s *AddressSuggester) Suggest(ctx context.Context, tenantID shared.ID) (*AddressSuggestions, error) {
	if s == nil || s.store == nil || s.gate == nil {
		return nil, errors.New("address suggestions are not wired")
	}
	if err := s.gate.ready(); err != nil {
		return nil, err
	}
	rows, err := s.store.ResolvedAddresses(ctx, tenantID, maxResolvedAddresses)
	if err != nil {
		return nil, err
	}
	auth, err := scopeauth.Load(ctx, tenantID, s.gate.scope, s.gate.roots)
	if err != nil {
		return nil, fmt.Errorf("load scope: %w", err)
	}
	visible, err := s.visible(ctx, tenantID, rows)
	if err != nil {
		return nil, err
	}
	out := &AddressSuggestions{Data: []AddressSuggestion{}}
	for _, r := range rows {
		if !visible(r.AssetID) || !scopedom.NeedsAuthority(r.Address) || scopedom.InternalName(r.Address) ||
			s.gate.denied(r.Address) {
			continue
		}
		if _, covered := auth.Covers(r.Address); covered {
			continue
		}
		var names []string
		for _, n := range r.Names {
			if !visible(n.AssetID) {
				continue
			}
			if _, ok := auth.Covers(n.Name); ok {
				names = append(names, n.Name)
			}
		}
		if len(names) == 0 {
			continue
		}
		if sharedAddressOf(r) {
			out.SkippedShared++
			continue
		}
		out.Data = append(out.Data, AddressSuggestion{Address: r.Address, AssetID: r.AssetID, Names: names, Provider: cloudProvider(r.Properties)})
	}
	return out, nil
}

// visible answers whether the caller may see an asset id.
func (s *AddressSuggester) visible(ctx context.Context, tenantID shared.ID, rows []ResolvedAddress) (func(string) bool, error) {
	if s.dataScope == nil {
		return func(string) bool { return true }, nil
	}
	ids := make([]shared.ID, 0, len(rows)*2)
	for _, r := range rows {
		if id, err := shared.IDFromString(r.AssetID); err == nil {
			ids = append(ids, id)
		}
		for _, n := range r.Names {
			if id, err := shared.IDFromString(n.AssetID); err == nil {
				ids = append(ids, id)
			}
		}
	}
	in, err := s.dataScope.FilterForCaller(ctx, tenantID, ids)
	if err != nil {
		return nil, fmt.Errorf("data scope: %w", err)
	}
	return func(raw string) bool {
		id, err := shared.IDFromString(raw)
		return err == nil && in(id)
	}, nil
}

// sharedAddressOf reports an edge/CDN address, or one that names of three or
// more registrable domains resolve to.
func sharedAddressOf(r ResolvedAddress) bool {
	if cdn, _ := r.Properties["cdn"].(string); cdn != "" {
		return true
	}
	org, _ := r.Properties["asn_org"].(string)
	l := strings.ToLower(org)
	for _, p := range edgeProviders {
		if l != "" && strings.Contains(l, p) {
			return true
		}
	}
	domains := map[string]bool{}
	for _, n := range r.Names {
		d, err := publicsuffix.EffectiveTLDPlusOne(strings.TrimSuffix(n.Name, "."))
		if err != nil {
			d = n.Name
		}
		domains[d] = true
	}
	return len(domains) >= sharedHostingDomains
}

// cloudProvider names the cloud provider of an address, "" when none.
func cloudProvider(props map[string]any) string {
	org, _ := props["asn_org"].(string)
	l := strings.ToLower(org)
	for _, p := range cloudProviders {
		if l != "" && strings.Contains(l, p) {
			return org
		}
	}
	return ""
}
