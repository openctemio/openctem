package easm

import "github.com/openctemio/openctem/api/pkg/domain/asset"

// internetFacingTypes are the stored asset types (after asset.CanonicalPair:
// http_service and open_port are services; website, api and discovered_url
// are applications) that EASM attribution governs (RFC-036 §6.3, §6.4):
// names and addresses a sensor reaches over the internet. Hosts (vulnerability
// scanner and agent inventories), code repositories, cloud resources and
// identities come from the tenant's own connectors and are not governed here.
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
