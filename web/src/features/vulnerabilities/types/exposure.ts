/**
 * The vulnerability page's answer for one CVE, inside the caller's data scope
 * (GET /api/v1/vulnerability-exposures/{id}, api/docs/architecture/vulnerability-page.md).
 */

export type ExposureVerdict = 'confirmed' | 'possible' | 'not_affected' | 'no_evidence'

export type PriorityKey = 'P0' | 'P1' | 'P2' | 'P3' | 'none'

export interface CveExposureComponent {
  product_id: string
  name: string
  purl?: string
  version: string
  fixed_versions: string[]
  recommended_fix?: string
  assets: number
  active_findings: number
}

export interface CveExposureUpgrade {
  product_id: string
  name: string
  target: string
  major_change: boolean
  fixes_findings: number
  on_assets: number
  no_fix_findings: number
}

export interface CveExposureSource {
  name: string
  source: string
  assets: number
}

export interface CveAlias {
  id: string
  source: string
  synced_at: string
}

export interface FeedFreshness {
  source: 'kev' | 'epss' | 'vulnfeed' | string
  last_sync_at?: string
  status: string
}

export interface CveEmergingAlert {
  id: string
  state: string
  level: string
  tier: string
}

export interface CveExposure {
  cve_id: string
  in_catalog: boolean
  verdict: ExposureVerdict
  findings: {
    total: number
    active: number
    by_status: Record<string, number>
    by_priority: Partial<Record<PriorityKey, number>>
    worst_priority: '' | 'P0' | 'P1' | 'P2' | 'P3'
    in_task: number
    not_in_task: number
  }
  assets: {
    impacted: number
    crown_jewels: number
    internet_facing: number
    with_findings: number
  }
  possible: { assets: number; products: string[] }
  not_affected: { assets: number; products: string[] }
  components: CveExposureComponent[]
  upgrades: CveExposureUpgrade[]
  sources: CveExposureSource[]
  single_source_assets: number
  timeline: {
    first_seen_at?: string
    last_seen_at?: string
    last_fixed_at?: string
    fixed: number
    reopened: number
    last_reopened_at?: string
  }
  intel: {
    aliases: CveAlias[]
    cwes: string[]
    feeds: FeedFreshness[]
    emerging?: CveEmergingAlert
  }
}

export interface CveExposureAsset {
  asset_id: string
  name: string
  asset_type: string
  criticality: string
  crown_jewel: boolean
  internet_facing: boolean
  owner: string
  open_findings: number
  total_findings: number
  worst_priority: '' | 'P0' | 'P1' | 'P2' | 'P3'
  worst_severity: string
  last_seen_at?: string
  /** Where on the asset the findings point: "443/tcp", a URL path or a file (producer text). */
  targets?: string[]
  targets_more?: boolean
}

export interface CveExposureAssetsResponse {
  data: CveExposureAsset[]
  total: number
  page: number
  per_page: number
  total_pages: number
}
