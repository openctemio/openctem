package handler

// Edge labels on assets and scope entries (research/259 edge addresses,
// owner decision 2026-10-30 in research/274): the platform labels a CDN,
// edge, SaaS-hosting or cloud-shared address and the name served through
// one; it never refuses to scan them by itself. The organization decides by
// adding the address to out of scope (the scope exclusion path).
//
// The label is computed on read from the asset's own properties or the
// entry's pattern by the one address classifier (pkg/domain/edgeaddr): no
// stored copy can drift from the dataset, and no extra query runs.

import (
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/edgeaddr"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/scope/ipset"
)

// EdgeLabel says the asset or entry is served by, or is, a provider's
// shared address.
type EdgeLabel struct {
	// Class: edge, saas_hosting or cloud_shared.
	Class    string `json:"class"`
	Provider string `json:"provider"`
	// Address is set when the asset or entry IS the provider's address (an
	// IP asset, an address or range entry): the pattern that adding it to
	// out of scope takes. Absent for a name served through the provider.
	Address string `json:"address,omitempty"`
}

func edgeLabel(r edgeaddr.Result, address string) *EdgeLabel {
	if !r.Shared() || r.Provider == "" {
		return nil
	}
	return &EdgeLabel{Class: string(r.Class), Provider: r.Provider, Address: address}
}

// assetEdgeLabel labels an IP asset inside a provider's space, and a name or
// service served through a provider; nil otherwise.
func assetEdgeLabel(a *asset.Asset) *EdgeLabel {
	if a == nil {
		return nil
	}
	c := edgeaddr.Default()
	props := a.Properties()
	cdn := firstString(asset.PropertyStrings(props, "cdn"))
	switch a.Type() {
	case asset.AssetTypeIPAddress:
		r := c.Address(a.Name(), cdn, firstString(asset.PropertyStrings(props, "asn_org")))
		return edgeLabel(r, strings.TrimSpace(a.Name()))
	case asset.AssetTypeDomain, asset.AssetTypeSubdomain:
		return edgeLabel(c.Name(a.Name(), asset.PropertyStrings(props, "cname_target"), asset.IPAddresses(props)), "")
	}
	if cdn != "" {
		return edgeLabel(c.Address("", cdn, ""), "")
	}
	if cn := asset.PropertyStrings(props, "cname_target"); len(cn) > 0 {
		return edgeLabel(c.Name("", cn, nil), "")
	}
	return nil
}

// scopeEntryEdgeLabel labels an address, range or CIDR entry that lies
// wholly inside a provider's published range, and a name entry under a
// provider's host suffix.
func scopeEntryEdgeLabel(targetType scopedom.TargetType, pattern string) *EdgeLabel {
	c := edgeaddr.Default()
	switch targetType {
	case scopedom.TargetTypeIPAddress, scopedom.TargetTypeIPRange, scopedom.TargetTypeCIDR:
		rg, ok := ipset.Parse(pattern)
		if !ok {
			return nil
		}
		return edgeLabel(c.Range(rg.Lo, rg.Hi), strings.TrimSpace(pattern))
	case scopedom.TargetTypeDomain, scopedom.TargetTypeSubdomain:
		return edgeLabel(c.Host(strings.TrimPrefix(strings.TrimSpace(pattern), "*.")), "")
	}
	return nil
}

func firstString(v []string) string {
	if len(v) == 0 {
		return ""
	}
	return v[0]
}
