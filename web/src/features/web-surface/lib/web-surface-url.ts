/**
 * Request URLs of the web surface views (RFC-056). Pure, so the filters a
 * page sends are tested without a network. Every list takes `page` and
 * `per_page` (the list query contract) and only the filters set.
 */

export const WEB_SURFACE_TABS = ['origins', 'endpoints', 'patterns', 'changes'] as const
export type WebSurfaceTab = (typeof WEB_SURFACE_TABS)[number]

export function isWebSurfaceTab(v: string): v is WebSurfaceTab {
  return (WEB_SURFACE_TABS as readonly string[]).includes(v)
}

/** The filters of the endpoint list (and of the grouped views). */
export interface EndpointFilters {
  q?: string
  originAssetId?: string
  pathHash?: string
  method?: string
  kind?: string
  authState?: string
  /** Only endpoints under a scope exclusion (recorded, never tested). */
  excludedOnly?: boolean
  /** Only endpoints on the sensitive-path catalog. */
  sensitiveOnly?: boolean
  /** Ignored endpoints are hidden unless asked for. */
  includeIgnored?: boolean
}

export interface PageQuery {
  page: number
  perPage: number
}

function base(page: PageQuery): URLSearchParams {
  return new URLSearchParams({ page: String(page.page), per_page: String(page.perPage) })
}

/** The endpoint filter params, shared by the list, stats, patterns and origins. */
export function endpointFilterParams(
  f: EndpointFilters,
  params = new URLSearchParams()
): URLSearchParams {
  const q = f.q?.trim()
  if (q) params.set('q', q)
  if (f.originAssetId) params.set('origin_asset_id', f.originAssetId)
  if (f.pathHash) params.set('path_hash', f.pathHash)
  if (f.method) params.set('method', f.method)
  if (f.kind) params.set('kind', f.kind)
  if (f.authState) params.set('auth_state', f.authState)
  if (f.excludedOnly) params.set('in_scope', 'false')
  if (f.sensitiveOnly) params.set('sensitive', 'true')
  if (!f.includeIgnored) params.set('state', 'active,gone')
  return params
}

export function endpointsUrl(f: EndpointFilters, page: PageQuery): string {
  return `/api/v1/web-endpoints?${endpointFilterParams(f, base(page)).toString()}`
}

export function endpointStatsUrl(f: EndpointFilters): string {
  const p = endpointFilterParams(f).toString()
  return p ? `/api/v1/web-endpoints/stats?${p}` : '/api/v1/web-endpoints/stats'
}

export function originsUrl(f: EndpointFilters, page: PageQuery): string {
  return `/api/v1/web-origins?${endpointFilterParams(f, base(page)).toString()}`
}

export function patternsUrl(f: EndpointFilters, page: PageQuery): string {
  return `/api/v1/web-path-patterns?${endpointFilterParams(f, base(page)).toString()}`
}

export interface EventFilters {
  kind?: string
  originAssetId?: string
  sensitiveOnly?: boolean
  /** RFC 3339 lower bound. */
  since?: string
}

export function eventsUrl(f: EventFilters, page: PageQuery): string {
  const p = base(page)
  if (f.kind) p.set('kind', f.kind)
  if (f.originAssetId) p.set('origin_asset_id', f.originAssetId)
  if (f.sensitiveOnly) p.set('sensitive', 'true')
  if (f.since) p.set('at_gte', f.since)
  return `/api/v1/web-endpoint-events?${p.toString()}`
}

export function endpointUrl(id: string): string {
  return `/api/v1/web-endpoints/${encodeURIComponent(id)}`
}

export function endpointParamsUrl(id: string): string {
  return `${endpointUrl(id)}/parameters`
}

export const CATALOG_URL = '/api/v1/web-path-catalog'
