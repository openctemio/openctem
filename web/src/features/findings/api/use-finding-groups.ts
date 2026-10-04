'use client'

import useSWR from 'swr'
import { get } from '@/lib/api/client'

// ============================================
// Types
// ============================================

export interface FindingGroupStats {
  total: number
  open: number
  in_progress: number
  fix_applied: number
  resolved: number
  affected_assets: number
  resolved_assets: number
  progress_pct: number
}

export interface FindingGroup {
  group_key: string
  group_type: string
  label: string
  severity: string
  metadata: Record<string, unknown>
  stats: FindingGroupStats
}

export interface FindingGroupsResponse {
  data: FindingGroup[]
  pagination: {
    total: number
    page: number
    per_page: number
  }
}

export interface RelatedCVE {
  cve_id: string
  title: string
  severity: string
  finding_count: number
}

export interface RelatedCVEsResponse {
  source_cve: string
  related_cves: RelatedCVE[]
}

export type GroupByDimension =
  | 'cve_id'
  | 'rule_id'
  | 'asset_id'
  | 'owner_id'
  | 'component_id'
  | 'severity'
  | 'source'
  | 'finding_type'
  | 'family'

export interface FindingGroupsFilters {
  group_by: GroupByDimension
  severities?: string
  statuses?: string
  sources?: string
  cve_ids?: string
  asset_tags?: string
  assigned_to_me?: boolean
  page?: number
  per_page?: number
  /** A saved view the groups run (its filter, with these filters on top). */
  view?: string
}

// ============================================
// Hooks
// ============================================

export function buildGroupsUrl(filters: FindingGroupsFilters): string {
  const params = new URLSearchParams()
  params.set('group_by', filters.group_by)
  // The list query contract's param names (RFC-048); the old plural names
  // are deprecated aliases on the server.
  if (filters.severities) params.set('severity', filters.severities)
  if (filters.statuses) params.set('status', filters.statuses)
  if (filters.sources) params.set('source', filters.sources)
  if (filters.cve_ids) params.set('cve_id', filters.cve_ids)
  if (filters.asset_tags) params.set('asset_tag', filters.asset_tags)
  if (filters.assigned_to_me) params.set('related_to', 'me')
  if (filters.view) params.set('view', filters.view)
  if (filters.page) params.set('page', String(filters.page))
  if (filters.per_page) params.set('per_page', String(filters.per_page))
  return `/api/v1/findings/groups?${params.toString()}`
}

export function useFindingGroups(filters: FindingGroupsFilters) {
  const url = buildGroupsUrl(filters)

  return useSWR<FindingGroupsResponse>(url, (u: string) => get<FindingGroupsResponse>(u), {
    revalidateOnFocus: false,
    dedupingInterval: 30000, // 30s stale-while-revalidate
  })
}

export function useRelatedCVEs(cveId: string | null, assetTags?: string) {
  const url = cveId
    ? `/api/v1/findings/related-cves/${encodeURIComponent(cveId)}${assetTags ? `?asset_tags=${assetTags}` : ''}`
    : null

  return useSWR<RelatedCVEsResponse>(url, (u: string) => get<RelatedCVEsResponse>(u), {
    revalidateOnFocus: false,
  })
}
