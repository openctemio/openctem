/**
 * The vulnerabilities list: one row per CVE over the findings the caller may
 * see (GET /api/v1/vulnerability-exposures, api/docs/architecture/vulnerability-page.md).
 */

export interface VulnListEmerging {
  id: string
  level: 'immediate' | 'digest' | 'listed' | string
  state: string
}

export interface VulnListProduct {
  name: string
  versions: string[]
  findings: number
}

export interface VulnListItem {
  cve_id: string
  in_catalog: boolean
  title: string
  aliases: string[]
  severity: string
  cvss_score?: number
  cvss_version?: string
  epss_score?: number
  epss_percentile?: number
  kev: boolean
  kev_due_date?: string
  kev_ransomware: boolean
  exploit: boolean
  exploit_maturity: string
  emerging?: VulnListEmerging
  worst_priority: '' | 'P0' | 'P1' | 'P2' | 'P3'
  findings: number
  open_findings: number
  assets: number
  internet_facing_assets: number
  crown_jewel_assets: number
  products: VulnListProduct[]
  fixed_versions: string[]
  has_fix: boolean
  past_sla: number
  next_sla_due?: string
  in_task: number
  first_seen_at?: string
  last_seen_at?: string
}

export interface VulnListSummary {
  total: number
  kev: number
  exploit: number
  emerging: number
  past_sla: number
}

export interface VulnListResponse {
  data: VulnListItem[]
  total: number
  page: number
  per_page: number
  total_pages: number
  summary: VulnListSummary
}
