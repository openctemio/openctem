package asset

// Property keys used when assets flow through ingest / validation /
// property-unpack paths. Kept in one place so downstream consumers
// (ingest processors, scanner output parsers, validators) don't drift
// with raw string keys.
//
// These are the JSON keys in Asset.Properties as defined by the CTIS
// ingest schema. Changing any value here is a wire-format break.
const (
	// PropKeyDiscoverySource is where the asset came from
	// (dns, cert_transparency, bruteforce, passive, manual, ...).
	PropKeyDiscoverySource = "discovery_source"
	// PropKeyDiscoveryTool names the specific tool that found the
	// asset when the source was a tool run (subfinder, amass, ...).
	PropKeyDiscoveryTool = "discovery_tool"
)

// Property keys the platform owns. They record decisions made by people or by
// the platform itself, and the platform reads them as such:
//
//   - is_crown_jewel is not a property at all: the flag is the
//     assets.is_crown_jewel column (migration 000463), written only by
//     PATCH /assets/{id}/crown-jewel. The key stays reserved so a client or a
//     sensor cannot plant a look-alike value in properties;
//   - business_impact_score / business_impact_notes are set on the asset's
//     business-impact form and feed risk scoring;
//   - aliases holds the asset's former names, written by asset identity
//     resolution when an asset is renamed, and used to match reports to it.
//
// A sensor report's free-form properties must never set them: a sensor could
// otherwise promote or demote a crown jewel, or attach another asset's name.
const (
	PropKeyIsCrownJewel        = "is_crown_jewel"
	PropKeyBusinessImpactScore = "business_impact_score"
	PropKeyBusinessImpactNotes = "business_impact_notes"
	PropKeyAliases             = "aliases"
)

// reservedPropertyKeys are the keys ingest drops from sensor-supplied
// properties: the platform-owned keys above plus the discovery fields, which
// ingest sets from the report's own discovery data.
var reservedPropertyKeys = map[string]bool{
	PropKeyIsCrownJewel:        true,
	PropKeyBusinessImpactScore: true,
	PropKeyBusinessImpactNotes: true,
	PropKeyAliases:             true,
	PropKeyDiscoverySource:     true,
	PropKeyDiscoveryTool:       true,
}

// IsReservedPropertyKey reports whether a top-level property key is owned by
// the platform and must not be taken from a sensor report.
func IsReservedPropertyKey(key string) bool {
	return reservedPropertyKeys[key]
}
