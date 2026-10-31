/**
 * Attack surface > Technologies: request URLs, the drill-down link to the
 * asset inventory and the CSV of the technology list. Pure, so the filters a
 * page sends and the file it exports are tested without a network. Every
 * name, version and vendor is scan output.
 */
import { buildCsv } from '@/hooks/use-csv-export'

export const TECHNOLOGIES_URL = '/api/v1/attack-surface/technologies'

export const TECHNOLOGY_CATEGORIES = [
  'web_server',
  'framework',
  'language',
  'js_library',
  'cdn',
  'hosting',
  'waf',
  'analytics',
  'security_header',
  'other',
] as const
export type TechnologyCategory = (typeof TECHNOLOGY_CATEGORIES)[number]

export function isTechnologyCategory(v: string): v is TechnologyCategory {
  return (TECHNOLOGY_CATEGORIES as readonly string[]).includes(v)
}

/** The version filter: every row, known versions only, or unknown only. */
export const VERSION_FILTERS = ['known', 'unknown'] as const
export type VersionFilter = (typeof VERSION_FILTERS)[number]

export function isVersionFilter(v: string): v is VersionFilter {
  return (VERSION_FILTERS as readonly string[]).includes(v)
}

/** One row of GET /attack-surface/technologies: a technology at one version. */
export interface TechnologyRow {
  key: string
  name: string
  version: string
  version_known: boolean
  category: string
  vendor?: string
  cpe?: string
  sources: string[]
  asset_count: number
  cve_count: number
  top_cve?: string
  top_cvss?: number
  kev: boolean
  exploit_available: boolean
  active_alerts: number
  first_seen: string
  last_seen: string
}

/** GET /attack-surface/technologies/stats. */
export interface TechnologyStats {
  total: number
  with_cves: number
  kev: number
  unknown_version: number
  with_alerts: number
}

export interface TechnologyFilters {
  q?: string
  category?: TechnologyCategory
  version?: VersionFilter
  /** Only versions with a CVE in the corpus. */
  withCves?: boolean
  /** Only versions with a known-exploited CVE. */
  kev?: boolean
}

export function technologyFilterParams(f: TechnologyFilters): URLSearchParams {
  const p = new URLSearchParams()
  const q = f.q?.trim()
  if (q) p.set('q', q)
  if (f.category) p.set('category', f.category)
  if (f.version) p.set('version_known', f.version === 'known' ? 'true' : 'false')
  if (f.withCves) p.set('has_cves', 'true')
  if (f.kev) p.set('kev', 'true')
  return p
}

export function technologiesUrl(
  f: TechnologyFilters,
  page: { page: number; perPage: number },
  sort?: string
): string {
  const p = technologyFilterParams(f)
  if (sort) p.set('sort', sort)
  p.set('page', String(page.page))
  p.set('per_page', String(page.perPage))
  return `${TECHNOLOGIES_URL}?${p.toString()}`
}

/** The counts strip ignores its own toggles so each count stays clickable. */
export function technologyStatsUrl(f: TechnologyFilters): string {
  const p = technologyFilterParams({ q: f.q, category: f.category }).toString()
  return p ? `${TECHNOLOGIES_URL}/stats?${p}` : `${TECHNOLOGIES_URL}/stats`
}

/**
 * The asset inventory filtered to the assets that run this exact version; an
 * unknown version is sent as an empty technology_version, which the API reads
 * as "the version is unknown".
 */
export function technologyAssetsHref(row: Pick<TechnologyRow, 'key' | 'version'>): string {
  const p = new URLSearchParams()
  p.set('technology', row.key)
  p.set('technology_version', row.version)
  return `/assets?${p.toString()}`
}

/** CSV of technology rows; cells go through buildCsv (formula injection safe). */
export function technologiesCsv(
  rows: TechnologyRow[],
  headers: [string, string, string, string, string, string, string, string, string, string]
): string {
  return buildCsv(
    headers,
    rows.map((r) => [
      r.name,
      r.version,
      r.vendor ?? '',
      r.category,
      r.asset_count,
      r.cve_count,
      r.top_cve ?? '',
      r.top_cvss ?? '',
      r.kev ? 'KEV' : r.exploit_available ? 'exploit' : '',
      r.sources.join(' '),
    ])
  )
}
