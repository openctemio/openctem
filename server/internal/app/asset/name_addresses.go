package asset

// The addresses a name resolves to, with their history (research/531): an
// address inside a range a provider publishes for infrastructure many
// organizations share is recorded on the name, not as an address asset, so
// the name's detail is where its addresses are read. Every source's record
// is kept (first seen, last seen, removed); nothing here writes.

import (
	"context"
	"fmt"
	"sort"
	"time"

	assetdom "github.com/openctemio/openctem/server/pkg/domain/asset"
	"github.com/openctemio/openctem/server/pkg/domain/edgeaddr"
)

// maxNameAddresses bounds the addresses one read returns (current ones
// first); the rest is counted in Truncated.
const maxNameAddresses = 2000

// NameAddressSource is one source's record of an address.
type NameAddressSource struct {
	Kind      string
	Name      string
	FirstSeen time.Time
	LastSeen  time.Time
	RemovedAt *time.Time
}

// NameAddress is one address the name resolved to, over every source.
type NameAddress struct {
	Address string
	// Provider and Class are set for an address inside a provider's
	// published shared range (edgeaddr SharedFrontEnd), empty otherwise.
	Provider string
	Class    string
	// Current: at least one source still reports it.
	Current   bool
	FirstSeen time.Time
	LastSeen  time.Time
	// RemovedAt is the latest removal when no source reports it any more.
	RemovedAt *time.Time
	Sources   []NameAddressSource
}

// NameAddresses is a name's addresses: current ones first, then by
// provider and address.
type NameAddresses struct {
	Items []NameAddress
	// Truncated counts the addresses left out past maxNameAddresses.
	Truncated int
}

// GetNameAddresses returns the addresses the tenant's domain or subdomain
// asset resolved to, from its per-source ip_addresses records. The asset is
// read in the caller's data scope (out of scope answers not found); any
// other asset type has none.
func (s *AssetService) GetNameAddresses(ctx context.Context, tenantID, assetID string) (*NameAddresses, error) {
	a, err := s.GetAssetInCallerScope(ctx, tenantID, assetID)
	if err != nil {
		return nil, err
	}
	out := &NameAddresses{Items: []NameAddress{}}
	repo := s.setRepo()
	if repo == nil || (a.Type() != assetdom.AssetTypeDomain && a.Type() != assetdom.AssetTypeSubdomain) {
		return out, nil
	}
	rows, err := repo.ListSetElements(ctx, a.TenantID(), a.ID())
	if err != nil {
		return nil, fmt.Errorf("list name addresses: %w", err)
	}
	out.Items, out.Truncated = foldNameAddresses(rows, edgeaddr.Default())
	return out, nil
}

// foldNameAddresses folds the per-source ip_addresses records into one row
// per address.
func foldNameAddresses(rows []assetdom.SetElement, c *edgeaddr.Classifier) ([]NameAddress, int) {
	byAddr := map[string]*NameAddress{}
	order := []string{}
	for _, e := range rows {
		if e.Attribute != assetdom.SetAttrIPAddresses {
			continue
		}
		na, ok := byAddr[e.Element]
		if !ok {
			na = &NameAddress{Address: e.Element, FirstSeen: e.FirstSeen, LastSeen: e.LastSeen}
			if r, shared := c.SharedFrontEnd(e.Element); shared {
				na.Provider, na.Class = r.Provider, string(r.Class)
			}
			byAddr[e.Element] = na
			order = append(order, e.Element)
		}
		if e.FirstSeen.Before(na.FirstSeen) {
			na.FirstSeen = e.FirstSeen
		}
		if e.LastSeen.After(na.LastSeen) {
			na.LastSeen = e.LastSeen
		}
		if e.RemovedAt == nil {
			na.Current = true
		} else if na.RemovedAt == nil || e.RemovedAt.After(*na.RemovedAt) {
			t := *e.RemovedAt
			na.RemovedAt = &t
		}
		na.Sources = append(na.Sources, NameAddressSource{Kind: string(e.Kind), Name: e.Name,
			FirstSeen: e.FirstSeen, LastSeen: e.LastSeen, RemovedAt: e.RemovedAt})
	}
	items := make([]NameAddress, 0, len(order))
	for _, k := range order {
		na := byAddr[k]
		if na.Current {
			na.RemovedAt = nil
		}
		items = append(items, *na)
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].Current != items[j].Current {
			return items[i].Current
		}
		if items[i].Provider != items[j].Provider {
			return items[i].Provider < items[j].Provider
		}
		return items[i].Address < items[j].Address
	})
	if len(items) > maxNameAddresses {
		return items[:maxNameAddresses], len(items) - maxNameAddresses
	}
	return items, 0
}
