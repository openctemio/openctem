// Package ctemid models the CTEM-ID catalog: a standardized, CVE-like set of
// exposure-class identifiers published as an external JSON feed. Unlike a CVE
// (a specific software flaw), a CTEM-ID names a class of exposure — brand
// impersonation, credential dumps, lookalike domains, ransomware activity,
// source-code exposure, system exposure, and so on. It is tenant-agnostic
// reference data that findings and exposures can be tagged with.
package ctemid

import "strings"

// Category is the exposure class a CTEM-ID belongs to.
type Category string

const (
	CategoryBrandImpersonation Category = "brand_impersonation"
	CategoryCredentialDumps    Category = "credential_dumps"
	CategoryInfectedDevices    Category = "infected_devices"
	CategoryLookalikeDomains   Category = "lookalike_domains"
	CategoryRansomware         Category = "ransomware"
	CategorySourceCodeExposure Category = "source_code_exposure"
	CategorySystemExposure     Category = "system_exposure"
	CategoryOther              Category = "other"
)

// String returns the string representation.
func (c Category) String() string { return string(c) }

// knownCategories maps feed-provided category/type strings (loosely) onto the
// canonical categories. The feed vocabulary is not guaranteed, so unrecognized
// values normalize to CategoryOther rather than being rejected — the catalog is
// fail-open reference data.
var knownCategories = map[string]Category{
	"brand_impersonation":  CategoryBrandImpersonation,
	"brand impersonation":  CategoryBrandImpersonation,
	"credential_dumps":     CategoryCredentialDumps,
	"credential dumps":     CategoryCredentialDumps,
	"credential_leak":      CategoryCredentialDumps,
	"infected_devices":     CategoryInfectedDevices,
	"infected devices":     CategoryInfectedDevices,
	"lookalike_domains":    CategoryLookalikeDomains,
	"lookalike domains":    CategoryLookalikeDomains,
	"ransomware":           CategoryRansomware,
	"source_code_exposure": CategorySourceCodeExposure,
	"source code exposure": CategorySourceCodeExposure,
	"system_exposure":      CategorySystemExposure,
	"system exposure":      CategorySystemExposure,
}

// ParseCategory normalizes a feed-provided category string to a canonical
// Category. Empty or unrecognized input maps to CategoryOther.
func ParseCategory(s string) Category {
	key := strings.ToLower(strings.TrimSpace(s))
	if key == "" {
		return CategoryOther
	}
	if c, ok := knownCategories[key]; ok {
		return c
	}
	// Tolerate hyphen/space variants by folding to underscore.
	folded := strings.ReplaceAll(key, "-", "_")
	folded = strings.ReplaceAll(folded, " ", "_")
	if c, ok := knownCategories[folded]; ok {
		return c
	}
	return CategoryOther
}
