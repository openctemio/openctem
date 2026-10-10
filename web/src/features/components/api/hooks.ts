'use client'

/**
 * Software components inventory API hooks (api/docs/rfcs/RFC-070-software-components-inventory.md).
 * Every list is paged and filtered on the server; the API applies the
 * caller's data scope.
 */

import useSWR, { type SWRConfiguration } from 'swr'
import { get, post } from '@/lib/api/client'
import { useTenant } from '@/context/tenant-provider'
import { usePermissions, Permission } from '@/lib/permissions'
import type {
  ComponentDetail,
  ComponentFilters,
  ComponentListResponse,
  ComponentSummary,
  ComponentUsage,
  ComponentVersion,
  ComponentVulnerability,
  DependencyGraph,
  GraphNode,
  ListResponse,
  SbomImportResult,
} from './types'

const BASE = '/api/v1/components'

const swrConfig: SWRConfiguration = {
  revalidateOnFocus: false,
  keepPreviousData: true,
  shouldRetryOnError: (error: { statusCode?: number }) =>
    !(error?.statusCode && error.statusCode >= 400 && error.statusCode < 500),
  errorRetryCount: 2,
}

/** Query string of the non-empty values, in a stable order. */
export function toQuery(params: Record<string, string | number | undefined | null>): string {
  const q = new URLSearchParams()
  for (const key of Object.keys(params).sort()) {
    const v = params[key]
    if (v === undefined || v === null || v === '') continue
    q.set(key, String(v))
  }
  const s = q.toString()
  return s ? `?${s}` : ''
}

export interface ComponentListParams extends ComponentFilters {
  page?: number
  per_page?: number
  sort?: string
}

export function componentsListUrl(params: ComponentListParams, facets = true): string {
  return `${BASE}${toQuery({ ...params, facets: facets ? 'true' : undefined })}`
}

function useCanRead() {
  const { currentTenant } = useTenant()
  const { can } = usePermissions()
  return Boolean(currentTenant) && can(Permission.ComponentsRead)
}

export function useComponentsList(params: ComponentListParams) {
  const enabled = useCanRead()
  const { data, error, isLoading, mutate } = useSWR<ComponentListResponse>(
    enabled ? componentsListUrl(params) : null,
    (url: string) => get<ComponentListResponse>(url),
    swrConfig
  )
  return { data, error, isLoading, mutate }
}

export function useComponentsSummary(filters: ComponentFilters) {
  const enabled = useCanRead()
  const { data, error, isLoading } = useSWR<ComponentSummary>(
    enabled ? `${BASE}/summary${toQuery({ ...filters })}` : null,
    (url: string) => get<ComponentSummary>(url),
    swrConfig
  )
  return { data, error, isLoading }
}

export function useComponent(id: string | null) {
  const enabled = useCanRead()
  const { data, error, isLoading } = useSWR<ComponentDetail>(
    enabled && id ? `${BASE}/${encodeURIComponent(id)}` : null,
    (url: string) => get<ComponentDetail>(url),
    swrConfig
  )
  return { data, error, isLoading }
}

export interface ComponentVersionRef {
  id: string
  component_id: string
  name: string
  version: string
  ecosystem: string
  purl: string
}

/**
 * A package version by the id findings carry (component_id). Used by the
 * findings filter chips, which render outside the tenant provider in places;
 * the API is the authority on access.
 */
export function useComponentVersion(versionId: string | null) {
  const { data, error, isLoading } = useSWR<ComponentVersionRef>(
    versionId ? `${BASE}/versions/${encodeURIComponent(versionId)}` : null,
    (url: string) => get<ComponentVersionRef>(url),
    swrConfig
  )
  return { data, error, isLoading }
}

export function useComponentVersions(id: string | null) {
  const enabled = useCanRead()
  const { data, error, isLoading } = useSWR<{ data: ComponentVersion[] }>(
    enabled && id ? `${BASE}/${encodeURIComponent(id)}/versions` : null,
    (url: string) => get<{ data: ComponentVersion[] }>(url),
    swrConfig
  )
  return { versions: data?.data ?? [], error, isLoading }
}

export interface UsageParams {
  version_id?: string
  relationship?: string
  scope?: string
  page?: number
  per_page?: number
}

export function useComponentUsages(id: string | null, params: UsageParams) {
  const enabled = useCanRead()
  const { data, error, isLoading } = useSWR<ListResponse<ComponentUsage>>(
    enabled && id ? `${BASE}/${encodeURIComponent(id)}/assets${toQuery({ ...params })}` : null,
    (url: string) => get<ListResponse<ComponentUsage>>(url),
    swrConfig
  )
  return { data, error, isLoading }
}

export function useComponentVulnerabilities(
  id: string | null,
  params: { include_resolved?: boolean; page?: number; per_page?: number }
) {
  const enabled = useCanRead()
  const query = toQuery({
    include_resolved: params.include_resolved ? 'true' : undefined,
    page: params.page,
    per_page: params.per_page,
  })
  const { data, error, isLoading } = useSWR<ListResponse<ComponentVulnerability>>(
    enabled && id ? `${BASE}/${encodeURIComponent(id)}/vulnerabilities${query}` : null,
    (url: string) => get<ListResponse<ComponentVulnerability>>(url),
    swrConfig
  )
  return { data, error, isLoading }
}

export function useDependencyPaths(assetId: string | null, versionId: string | null) {
  const enabled = useCanRead()
  const { data, error, isLoading } = useSWR<{ data: GraphNode[][] }>(
    enabled && assetId && versionId
      ? `/api/v1/assets/${encodeURIComponent(assetId)}/dependency-paths${toQuery({ version_id: versionId, limit: 10 })}`
      : null,
    (url: string) => get<{ data: GraphNode[][] }>(url),
    swrConfig
  )
  return { paths: data?.data ?? [], error, isLoading }
}

export function useDependencyGraph(assetId: string | null, focusVersionId?: string | null) {
  const enabled = useCanRead()
  const { data, error, isLoading } = useSWR<DependencyGraph>(
    enabled && assetId
      ? `/api/v1/assets/${encodeURIComponent(assetId)}/dependency-graph${toQuery({ focus: focusVersionId ?? undefined })}`
      : null,
    (url: string) => get<DependencyGraph>(url),
    swrConfig
  )
  return { graph: data, error, isLoading }
}

/**
 * Import (or, with dryRun, preview) an SBOM for an asset. The document is
 * sent as JSON; the API refuses anything above 50 MB.
 */
export async function importSbom(
  assetId: string,
  document: unknown,
  dryRun: boolean
): Promise<SbomImportResult> {
  return post<SbomImportResult>(
    `${BASE}/import${toQuery({ asset_id: assetId, dry_run: dryRun ? 'true' : undefined })}`,
    document
  )
}
