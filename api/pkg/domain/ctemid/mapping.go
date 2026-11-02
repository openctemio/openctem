package ctemid

import (
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/credential"
	"github.com/openctemio/openctem/api/pkg/domain/exposure"
	"github.com/openctemio/openctem/api/pkg/domain/lookalike"
)

// Basis names the signal a code was chosen from, so a reader can see why an
// exposure carries it and which input to correct when it is wrong.
type Basis string

const (
	// BasisLookalikeTechnique: the technique that generated a lookalike domain.
	BasisLookalikeTechnique Basis = "lookalike_technique"
	// BasisCredentialDump: a leaked credential's public dump source and its
	// classification (the organization's own or a vendor's).
	BasisCredentialDump Basis = "credential_dump"
	// BasisAssetScope: the linked asset's scope (cloud, vendor, shadow).
	BasisAssetScope Basis = "asset_scope"
	// BasisAssetType: the linked asset's type (a firewall).
	BasisAssetType Basis = "asset_type"
)

// Asset is what the mapping reads of an exposure's linked asset.
type Asset struct {
	Type    asset.AssetType
	SubType string
	Scope   asset.Scope
	// InternetFacing: the asset is marked internet accessible or its
	// exposure is public.
	InternetFacing bool
}

// Input is one exposure as the mapping sees it. Details come from producers
// and are untrusted: they are only compared with fixed values.
type Input struct {
	EventType exposure.EventType
	Details   map[string]any
	// Asset is nil when the exposure has no linked asset or it was not loaded.
	Asset *Asset
}

// Mapping is the code chosen for an exposure and why.
type Mapping struct {
	Code  Code
	Basis Basis
}

// systemExposureTypes are the event types that report a system reachable from
// the internet: the systems class (EXP) of the catalog.
var systemExposureTypes = map[exposure.EventType]bool{
	exposure.EventTypePortOpen:            true,
	exposure.EventTypeServiceDetected:     true,
	exposure.EventTypeWebInterfaceExposed: true,
	exposure.EventTypeAPIExposed:          true,
	exposure.EventTypeMCPServerExposed:    true,
}

// Map returns the CTEM-ID code of an exposure, or false when the data we hold
// does not settle one. Codes no rule reaches today, and why, are listed in
// docs/architecture/ctem-id-mapping.md.
func Map(in Input) (Mapping, bool) {
	switch {
	case in.EventType == exposure.EventTypeLookalikeDomain:
		return mapLookalike(in.Details)
	case in.EventType == exposure.EventTypeCredentialLeaked:
		return mapCredential(in.Details)
	case in.EventType == exposure.EventTypeRepoPublic:
		return mapRepository(in.Asset)
	case systemExposureTypes[in.EventType]:
		return mapSystem(in.Asset)
	}
	return Mapping{}, false
}

// mapLookalike: a homoglyph lookalike is DOM-2; the other generators all make
// small spelling variations of the name (DOM-1). A lookalike with no known
// technique (an import, a future generator) gets no code.
func mapLookalike(details map[string]any) (Mapping, bool) {
	var tech lookalike.Technique
	switch v := details["technique"].(type) {
	case lookalike.Technique:
		tech = v
	case string:
		tech = lookalike.Technique(normalize(v))
	default:
		return Mapping{}, false
	}
	switch tech {
	case lookalike.TechHomoglyph:
		return Mapping{CodeDOM2, BasisLookalikeTechnique}, true
	case lookalike.TechOmission, lookalike.TechRepetition, lookalike.TechTransposition,
		lookalike.TechReplacement, lookalike.TechInsertion, lookalike.TechHyphenation,
		lookalike.TechBitflip, lookalike.TechTLD:
		return Mapping{CodeDOM1, BasisLookalikeTechnique}, true
	}
	return Mapping{}, false
}

// mapCredential: a credential found in a public dump (breach, dark web, paste
// site, underground forum) is CRD-1 when it is the organization's own
// (classification internal) and CRD-2 when it is a vendor's. Credentials from
// code, malware logs or web pages, and unclassified ones, get no code: the
// catalog classes for those need who owns the device or repository.
func mapCredential(details map[string]any) (Mapping, bool) {
	src, _ := details["source_type"].(string)
	if !credential.SourceType(normalize(src)).IsBreachSource() {
		return Mapping{}, false
	}
	cls, _ := details["classification"].(string)
	switch credential.Classification(normalize(cls)) {
	case credential.ClassificationInternal:
		return Mapping{CodeCRD1, BasisCredentialDump}, true
	case credential.ClassificationVendor:
		return Mapping{CodeCRD2, BasisCredentialDump}, true
	}
	return Mapping{}, false
}

// mapRepository: a public repository on a vendor's asset is SRC-3. Whether a
// repository of the organization is sanctioned or an employee's own is not
// recorded, so those get no code.
func mapRepository(a *Asset) (Mapping, bool) {
	if a != nil && a.Scope == asset.ScopeVendor {
		return Mapping{CodeSRC3, BasisAssetScope}, true
	}
	return Mapping{}, false
}

// mapSystem maps a system reachable from the internet by who runs it: a
// vendor (EXP-6), nobody known (shadow, EXP-5), a partner (no code: affiliate
// and contractor read differently), then by what it is: a firewall
// (gateway, EXP-3), a cloud system (EXP-4). The default scope (internal) says
// nothing about network placement, so EXP-1 and EXP-2 are never chosen.
func mapSystem(a *Asset) (Mapping, bool) {
	if a == nil || !a.InternetFacing {
		return Mapping{}, false
	}
	switch a.Scope {
	case asset.ScopeVendor:
		return Mapping{CodeEXP6, BasisAssetScope}, true
	case asset.ScopeShadow:
		return Mapping{CodeEXP5, BasisAssetScope}, true
	case asset.ScopePartner:
		return Mapping{}, false
	}
	// A firewall is the stored pair network/firewall; the legacy firewall type
	// name resolves to the same pair.
	if pair := asset.CanonicalPair(a.Type, a.SubType); pair.Type == asset.AssetTypeNetwork && pair.SubType == "firewall" {
		return Mapping{CodeEXP3, BasisAssetType}, true
	}
	if a.Scope == asset.ScopeCloud {
		return Mapping{CodeEXP4, BasisAssetScope}, true
	}
	return Mapping{}, false
}

func normalize(s string) string { return strings.ToLower(strings.TrimSpace(s)) }
