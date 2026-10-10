/**
 * Software components inventory API types (api/docs/rfcs/RFC-070-software-components-inventory.md).
 * A component is a package (one row per package URL identity); a version is
 * one version of it in use; a usage is one asset and manifest using a version.
 */

export interface SeverityCounts {
  critical: number
  high: number
  medium: number
  low: number
}

export type Relationship = 'direct' | 'transitive' | 'unknown'
export type DependencyScope = 'runtime' | 'development' | 'test' | 'optional' | 'build' | 'provided'

export interface ComponentPackage {
  id: string
  name: string
  namespace?: string
  ecosystem: string
  purl_type: string
  purl: string
  versions_in_use: number
  assets: number
  direct_links: number
  transitive_links: number
  vulnerabilities: SeverityCounts
  kev: number
  fix_available: boolean
  licenses: string[]
  risk_score: number
  first_seen_at: string
  last_seen_at: string
}

export interface ComponentHealth {
  latest_version?: string
  deprecated: boolean
  eol_date?: string
}

export interface ComponentDetail extends ComponentPackage {
  global: boolean
  description?: string
  homepage?: string
  health: ComponentHealth | null
}

export interface UpgradeAdvice {
  version: string
  breaking: boolean
  complete: boolean
}

export interface ComponentVersion {
  id: string
  version: string
  purl: string
  assets: number
  vulnerabilities: SeverityCounts
  kev: number
  fixed_versions: string[]
  upgrade?: UpgradeAdvice
  licenses: string[]
  first_seen_at: string
  last_seen_at: string
}

export interface ComponentUsage {
  id: string
  asset_id: string
  asset_name: string
  asset_type: string
  criticality: string
  component_id: string
  name: string
  ecosystem: string
  version_id: string
  version: string
  purl: string
  relationship: Relationship
  scope?: DependencyScope
  location?: string
  depth?: number
  channel?: string
  licenses: string[]
  open_findings: number
  first_seen_at: string
  last_seen_at: string
}

export interface ComponentVulnerability {
  vulnerability_id: string
  cve_id: string
  title: string
  severity: string
  cvss_score?: number
  epss_score?: number
  in_cisa_kev: boolean
  fixed_versions: string[]
  affected_versions: string[]
  affected_assets_count: number
  open_finding_count: number
  total_finding_count: number
  vex_status?: string
  first_detected_at: string
  last_seen_at: string
}

export interface FacetValue {
  value: string
  count: number
}

export type ComponentFacets = Partial<
  Record<
    'ecosystem' | 'license' | 'severity' | 'kev' | 'has_fix' | 'relationship' | 'scope',
    FacetValue[]
  >
>

export interface ListResponse<T> {
  data: T[]
  total: number
  page: number
  per_page: number
  total_pages: number
}

export interface ComponentListResponse extends ListResponse<ComponentPackage> {
  facets?: ComponentFacets
}

export interface ComponentSummary {
  packages: number
  versions: number
  assets: number
  vulnerable_packages: number
  kev_packages: number
  fixable_packages: number
  outdated: number | null
  license_violations: number | null
}

export interface GraphNode {
  id: string
  component_id: string
  version_id: string
  name: string
  version: string
  purl: string
  ecosystem: string
  relationship: Relationship
  scope?: DependencyScope
  location?: string
  depth?: number
  vulnerabilities: SeverityCounts
  kev: boolean
}

export interface GraphEdge {
  from: string
  to: string
}

export interface DependencyGraph {
  nodes: GraphNode[]
  edges: GraphEdge[]
  truncated: boolean
}

export interface SbomIssue {
  ref: string
  name?: string
  reason: string
}

export interface SbomImportResult {
  dry_run: boolean
  format: 'cyclonedx' | 'spdx'
  spec_version: string
  components_total: number
  components_imported: number
  components_skipped: number
  direct: number
  transitive: number
  edges: number
  licenses_found: number
  ecosystems: FacetValue[]
  issues: SbomIssue[]
  diff?: { added: number; removed: number; unchanged: number }
  written?: {
    products_created: number
    versions_created: number
    links_written: number
    edges_written: number
    links_removed: number
  }
}

export type SbomFormat = 'cyclonedx' | 'spdx'

/** The list filters, as the URL and the API carry them (comma lists). */
export interface ComponentFilters {
  q?: string
  ecosystem?: string
  license?: string
  severity?: string
  kev?: string
  has_fix?: string
  has_vulnerabilities?: string
  relationship?: string
  scope?: string
  asset_id?: string
  owner_id?: string
}
