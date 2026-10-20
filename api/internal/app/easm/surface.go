package easm

import (
	"net/netip"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
)

// internetFacingTypes are the stored asset types (after asset.CanonicalPair:
// http_service and open_port are services; website, api and discovered_url
// are applications) that EASM attribution governs (RFC-036 §6.3, §6.4):
// names and addresses a sensor reaches over the internet. Code repositories,
// cloud resources and identities come from the tenant's own connectors and are
// not governed here. A host is governed by what its name is, not by its type
// (see governed): a host named by a public DNS name or public address is
// held like a domain or an IP address.
var internetFacingTypes = map[asset.AssetType]bool{
	asset.AssetTypeDomain:      true,
	asset.AssetTypeSubdomain:   true,
	asset.AssetTypeIPAddress:   true,
	asset.AssetTypeCertificate: true,
	asset.AssetTypeService:     true,
	asset.AssetTypeApplication: true,
}

// heldForReviewOnCreate reports whether a new asset of the stored type that
// a sensor report creates gets an attribution record (needs_review from a
// scan, candidate from an unsolicited report): the internet-facing types,
// and networks (an address range a passive lookup reports, such as the
// ranges an autonomous system announces, is never the tenant's on a
// sensor's word). Networks are not governed elsewhere: an existing network
// without a record keeps having none.
func heldForReviewOnCreate(t asset.AssetType, subType string) bool {
	return internetFacing(t, subType) || asset.CanonicalPair(t, subType).Type == asset.AssetTypeNetwork
}

// internetFacing reports whether a stored (type, sub_type) is governed by
// EASM attribution.
func internetFacing(t asset.AssetType, subType string) bool {
	return internetFacingTypes[asset.CanonicalPair(t, subType).Type]
}

// governed reports whether an asset is under the EASM ownership check: an
// internet-facing type, or any other type (a host, whatever its source)
// whose name is a bare public DNS name or public IP address. The stored type
// is chosen by whoever creates the asset, so it cannot decide whether a name
// is held for scope coverage. Repositories are judged by repository entries.
func governed(a *asset.Asset) bool {
	if a.Type() == asset.AssetTypeRepository {
		return false
	}
	return internetFacing(a.Type(), a.SubType()) || publicBareName(a.Name())
}

// internalOnlyTLDs are suffixes that never resolve on the public internet
// beyond the ones scope.InternalName already knows.
var internalOnlyTLDs = map[string]bool{
	"corp": true, "home": true, "intranet": true, "private": true,
	"localdomain": true, "lan": true, "local": true, "internal": true,
	"localhost": true, "test": true, "invalid": true, "example": true,
}

// publicBareName reports whether name is exactly a public IP address or a
// public fully-qualified DNS name (no port, path, scheme, user or spaces).
// A short name with no dot (a host's NetBIOS name), a private or loopback
// address and an internal-only DNS name are not public.
func publicBareName(name string) bool {
	n := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	if n == "" || scopedom.InternalName(n) {
		return false
	}
	if ip, err := netip.ParseAddr(n); err == nil {
		return ip.IsValid()
	}
	if len(n) > 253 || strings.ContainsAny(n, "/:@ \t*_[]") {
		return false
	}
	labels := strings.Split(n, ".")
	if len(labels) < 2 {
		return false
	}
	for _, l := range labels {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for _, c := range l {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	tld := labels[len(labels)-1]
	for _, c := range tld {
		if c < 'a' || c > 'z' {
			return false
		}
	}
	return len(tld) >= 2 && !internalOnlyTLDs[tld]
}
