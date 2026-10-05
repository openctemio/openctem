package definition

// Lifecycle of a definition (RFC-044 §5.1).
type Lifecycle string

const (
	LifecyclePublished  Lifecycle = "published"
	LifecycleReserved   Lifecycle = "reserved"
	LifecycleRejected   Lifecycle = "rejected"
	LifecycleWithdrawn  Lifecycle = "withdrawn"
	LifecycleDisputed   Lifecycle = "disputed"
	LifecycleDeprecated Lifecycle = "deprecated"
	// LifecycleMerged: folded into another definition (MergedInto).
	LifecycleMerged Lifecycle = "merged"
)

// IsValid reports whether l is a known lifecycle.
func (l Lifecycle) IsValid() bool {
	switch l {
	case LifecyclePublished, LifecycleReserved, LifecycleRejected, LifecycleWithdrawn,
		LifecycleDisputed, LifecycleDeprecated, LifecycleMerged:
		return true
	}
	return false
}

// Source says who created or asserted something in the catalog: a trusted
// feed, the rule-catalog import, a report (a scanner or sensor: untrusted,
// RFC-040) or a tenant's user. It is a definition's origin and the
// asserted_by of identifiers, relations and taxonomy links.
type Source string

const (
	SourceCVEList     Source = "cve_list"
	SourceNVD         Source = "nvd"
	SourceOSV         Source = "osv"
	SourceGHSA        Source = "ghsa"
	SourceKEV         Source = "kev"
	SourceRuleCatalog Source = "rule_catalog"
	SourceReport      Source = "report"
	SourceTenant      Source = "tenant"
)

// IsValid reports whether s is a known source.
func (s Source) IsValid() bool {
	switch s {
	case SourceCVEList, SourceNVD, SourceOSV, SourceGHSA, SourceKEV, SourceRuleCatalog,
		SourceReport, SourceTenant:
		return true
	}
	return false
}

// IsTrustedFeed reports whether s is a platform feed or the rule-catalog
// import: the only sources of shared (global) content.
func (s Source) IsTrustedFeed() bool {
	switch s {
	case SourceCVEList, SourceNVD, SourceOSV, SourceGHSA, SourceKEV, SourceRuleCatalog:
		return true
	}
	return false
}

// AssertsAliases reports whether s may assert that two global identifiers
// name the same issue: only the feeds that publish alias sets (RFC-044 §5.5).
func (s Source) AssertsAliases() bool {
	return s == SourceOSV || s == SourceGHSA || s == SourceCVEList
}

// IsTenantSource reports whether s is a source a tenant-scoped definition or
// link may come from.
func (s Source) IsTenantSource() bool { return s == SourceReport || s == SourceTenant }

// RelationType of a definition_relations edge (RFC-044 §5.3). None of them is
// an alias: aliases are identifiers of one definition.
type RelationType string

const (
	// RelationUpstream: from (a distro advisory) bundles to (a library CVE).
	RelationUpstream RelationType = "upstream"
	// RelationRelated: different issues worth reading together.
	RelationRelated RelationType = "related"
	// RelationDetects: from (a rule, plugin or template) detects to.
	RelationDetects RelationType = "detects"
)

// IsValid reports whether r is a known relation.
func (r RelationType) IsValid() bool {
	return r == RelationUpstream || r == RelationRelated || r == RelationDetects
}

// Role of a definition on a finding (RFC-044 §5.7).
type Role string

const (
	// RolePrimary: the issue (ord 0, exactly one per finding).
	RolePrimary Role = "primary"
	// RoleDetectedBy: the scanner rule that found it, when the primary is an advisory.
	RoleDetectedBy Role = "detected_by"
	// RoleAdditional: another advisory of the same finding.
	RoleAdditional Role = "additional"
	// RoleAlias: an alias the report asserted that no feed has confirmed.
	RoleAlias Role = "alias"
	// RoleWeakness: a weakness link next to a primary rule.
	RoleWeakness Role = "weakness"
)

// IsValid reports whether r is a known role.
func (r Role) IsValid() bool {
	switch r {
	case RolePrimary, RoleDetectedBy, RoleAdditional, RoleAlias, RoleWeakness:
		return true
	}
	return false
}

// LinkSource says who linked a finding to a definition.
type LinkSource string

const (
	LinkSourceReport LinkSource = "report"
	LinkSourceFeed   LinkSource = "feed"
	LinkSourceUser   LinkSource = "user"
)

// IsValid reports whether s is a known link source.
func (s LinkSource) IsValid() bool {
	return s == LinkSourceReport || s == LinkSourceFeed || s == LinkSourceUser
}
