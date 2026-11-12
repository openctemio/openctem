// Package component is the read model of the software components inventory:
// package products of the software catalog, the versions an organization
// uses, where each is used and the dependency graph between them.
// Design: api/docs/rfcs/RFC-070-software-components-inventory.md.
package component

import "time"

// SeverityCounts are open findings by severity.
type SeverityCounts struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
}

// Total is the number of open findings counted.
func (s SeverityCounts) Total() int { return s.Critical + s.High + s.Medium + s.Low }

// Package is one row of the package list: a catalog product used by the
// caller's in-scope assets.
type Package struct {
	ID              string         `json:"id"`
	Name            string         `json:"name"`
	Namespace       string         `json:"namespace,omitempty"`
	Ecosystem       string         `json:"ecosystem"`
	PURLType        string         `json:"purl_type"`
	PURL            string         `json:"purl"`
	VersionsInUse   int            `json:"versions_in_use"`
	Assets          int            `json:"assets"`
	DirectLinks     int            `json:"direct_links"`
	TransitiveLinks int            `json:"transitive_links"`
	Vulnerabilities SeverityCounts `json:"vulnerabilities"`
	KEV             int            `json:"kev"`
	FixAvailable    bool           `json:"fix_available"`
	Licenses        []string       `json:"licenses"`
	RiskScore       int            `json:"risk_score"`
	FirstSeenAt     time.Time      `json:"first_seen_at"`
	LastSeenAt      time.Time      `json:"last_seen_at"`
}

// PackageDetail is a package with its descriptive fields.
type PackageDetail struct {
	Package
	// Global: the identity comes from the vulnerability feed; otherwise the
	// product is private to the organization.
	Global      bool    `json:"global"`
	Description string  `json:"description,omitempty"`
	Homepage    string  `json:"homepage,omitempty"`
	Health      *Health `json:"health"`
}

// Health is package health from the vulnerability feed (nil until the feed
// carries it).
type Health struct {
	LatestVersion string     `json:"latest_version,omitempty"`
	Deprecated    bool       `json:"deprecated"`
	EOLDate       *time.Time `json:"eol_date,omitempty"`
}

// Version is one version of a package in use.
type Version struct {
	ID              string         `json:"id"`
	Version         string         `json:"version"`
	PURL            string         `json:"purl"`
	Assets          int            `json:"assets"`
	Vulnerabilities SeverityCounts `json:"vulnerabilities"`
	KEV             int            `json:"kev"`
	FixedVersions   []string       `json:"fixed_versions"`
	Upgrade         *UpgradeAdvice `json:"upgrade,omitempty"`
	Licenses        []string       `json:"licenses"`
	FirstSeenAt     time.Time      `json:"first_seen_at"`
	LastSeenAt      time.Time      `json:"last_seen_at"`
}

// UpgradeAdvice is the nearest version that fixes the open findings of a
// version.
type UpgradeAdvice struct {
	Version string `json:"version"`
	// Breaking: the upgrade changes the major version.
	Breaking bool `json:"breaking"`
	// Complete: the version fixes every open finding (otherwise only some).
	Complete bool `json:"complete"`
}

// Usage is one place a package version is used: an asset and location.
type Usage struct {
	LinkID       string    `json:"id"`
	AssetID      string    `json:"asset_id"`
	AssetName    string    `json:"asset_name"`
	AssetType    string    `json:"asset_type"`
	Criticality  string    `json:"criticality"`
	ProductID    string    `json:"component_id"`
	Name         string    `json:"name"`
	Ecosystem    string    `json:"ecosystem"`
	VersionID    string    `json:"version_id"`
	Version      string    `json:"version"`
	PURL         string    `json:"purl"`
	Relationship string    `json:"relationship"`
	Scope        string    `json:"scope,omitempty"`
	Location     string    `json:"location,omitempty"`
	Depth        *int      `json:"depth,omitempty"`
	Channel      string    `json:"channel,omitempty"`
	Licenses     []string  `json:"licenses"`
	OpenFindings int       `json:"open_findings"`
	FirstSeenAt  time.Time `json:"first_seen_at"`
	LastSeenAt   time.Time `json:"last_seen_at"`
}

// Vulnerability is a vulnerability affecting a package, across its versions.
type Vulnerability struct {
	VulnerabilityID     string    `json:"vulnerability_id"`
	CVEID               string    `json:"cve_id"`
	Title               string    `json:"title"`
	Severity            string    `json:"severity"`
	CVSSScore           *float64  `json:"cvss_score,omitempty"`
	EPSSScore           *float64  `json:"epss_score,omitempty"`
	InCISAKEV           bool      `json:"in_cisa_kev"`
	FixedVersions       []string  `json:"fixed_versions"`
	AffectedVersions    []string  `json:"affected_versions"`
	AffectedAssetsCount int       `json:"affected_assets_count"`
	OpenFindingCount    int       `json:"open_finding_count"`
	TotalFindingCount   int       `json:"total_finding_count"`
	VEXStatus           string    `json:"vex_status,omitempty"`
	FirstDetectedAt     time.Time `json:"first_detected_at"`
	LastSeenAt          time.Time `json:"last_seen_at"`
}

// FacetValue is one value of a facet with its count.
type FacetValue struct {
	Value string `json:"value"`
	Count int    `json:"count"`
}

// Facets are the filter values present in the filtered package set.
type Facets map[string][]FacetValue

// Summary is the KPI strip of the inventory.
type Summary struct {
	Packages           int  `json:"packages"`
	Versions           int  `json:"versions"`
	Assets             int  `json:"assets"`
	VulnerablePackages int  `json:"vulnerable_packages"`
	KEVPackages        int  `json:"kev_packages"`
	FixablePackages    int  `json:"fixable_packages"`
	Outdated           *int `json:"outdated"`
	LicenseViolations  *int `json:"license_violations"`
}

// GraphNode is a package link in an asset's dependency graph.
type GraphNode struct {
	ID              string         `json:"id"`
	ProductID       string         `json:"component_id"`
	VersionID       string         `json:"version_id"`
	Name            string         `json:"name"`
	Version         string         `json:"version"`
	PURL            string         `json:"purl"`
	Ecosystem       string         `json:"ecosystem"`
	Relationship    string         `json:"relationship"`
	Scope           string         `json:"scope,omitempty"`
	Location        string         `json:"location,omitempty"`
	Depth           *int           `json:"depth,omitempty"`
	Vulnerabilities SeverityCounts `json:"vulnerabilities"`
	KEV             bool           `json:"kev"`
}

// GraphEdge: From depends on To.
type GraphEdge struct {
	From string `json:"from"`
	To   string `json:"to"`
}

// Graph is a bounded part of an asset's dependency graph.
type Graph struct {
	Nodes     []GraphNode `json:"nodes"`
	Edges     []GraphEdge `json:"edges"`
	Truncated bool        `json:"truncated"`
}

// Path is one introduction path, from a root link to the target link.
type Path []GraphNode

// SBOMEntry is one package of an SBOM export.
type SBOMEntry struct {
	ID                 string
	Name               string
	Version            string
	Ecosystem          string
	PURL               string
	Licenses           []string
	VulnerabilityCount int
}

// FindingComponent is the package version a finding is about, and how the
// finding's asset uses it.
type FindingComponent struct {
	VersionID    string
	ProductID    string
	Name         string
	Version      string
	Ecosystem    string
	PURL         string
	Licenses     []string
	Relationship string
	Scope        string
	Location     string
	Depth        *int
}
