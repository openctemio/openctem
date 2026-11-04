package ingest

// Private DNS zones (docs/architecture/sensors.md, "Collector sensors"): a
// cloud DNS collector reports each name with the visibility of the zone it
// is in (`zone_visibility`). A name in a private zone resolves only inside
// the organization's networks, so it is not internet-facing: its exposure
// is private, not the public default of a DNS name.

import (
	"github.com/openctemio/ctis/v2"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
)

// privateZone reports whether a reported DNS name is in a private zone: a
// domain_name the producer marks verified not reachable from the internet
// (is_internet_accessible: false, a DNS collector reading a private zone).
func privateZone(ca *ctis.Asset) bool {
	return ca != nil && ca.Type == ctis.AssetTypeDomainName &&
		ca.IsInternetAccessible != nil && !*ca.IsInternetAccessible
}

// applyPrivateZone marks a DNS asset created from a private-zone name as
// private and not internet-accessible, whatever the type's default.
func applyPrivateZone(a *asset.Asset, ca *ctis.Asset) {
	if !privateZone(ca) || (a.Type() != asset.AssetTypeDomain && a.Type() != asset.AssetTypeSubdomain) {
		return
	}
	a.SetExposure(asset.ExposurePrivate)
	a.SetInternetAccessible(false)
}
