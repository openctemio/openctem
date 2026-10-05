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

// internetFacing reports whether a stored (type, sub_type) is governed by
// EASM attribution.
func internetFacing(t asset.AssetType, subType string) bool {
	return internetFacingTypes[asset.CanonicalPair(t, subType).Type]
}
