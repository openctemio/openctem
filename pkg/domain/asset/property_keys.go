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
