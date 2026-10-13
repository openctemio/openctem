package ingest

// Private DNS zones (docs/architecture/sensors.md, "Collector sensors"): a
// cloud DNS collector reports each name with the visibility of the zone it
// is in (`zone_visibility`). A name in a private zone resolves only inside
// the organization's networks, so it is not internet-facing: its exposure
// is private, not the public default of a DNS name.

import (
	"strings"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
)

// propZoneVisibility is the property in which a DNS collector names the
// visibility of the zone a name is in ("public" or "private").
const propZoneVisibility = "zone_visibility"

// privateZone reports whether a reported DNS name is in a private zone.
func privateZone(ca *ctis.Asset) bool {
	if ca == nil || (ca.Type != ctis.AssetTypeDomain && ca.Type != ctis.AssetTypeSubdomain) {
		return false
	}
	v, _ := ca.Properties[propZoneVisibility].(string)
	return strings.EqualFold(strings.TrimSpace(v), "private")
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
