'use client'

/**
 * Web page monitoring (RFC-138): watched URLs, suggestions and detected
 * changes with their diff. Reads need assets:read (the API narrows them to the
 * caller's data scope); watch changes need scans:write.
 */

import useSWR from 'swr'
import useSWRInfinite from 'swr/infinite'
import { del, get, post, put } from '@/lib/api/client'
import { usePermissions, Permission } from '@/lib/permissions'
import { useTenantModules } from '@/features/integrations/api/use-tenant-modules'

export const PAGE_MONITOR_BASE = '/api/v1/easm/page-monitoring'
export const PAGE_WATCHES_KEY = `${PAGE_MONITOR_BASE}/watches`
export const PAGE_SUGGESTIONS_KEY = `${PAGE_MONITOR_BASE}/suggestions`

export type PageWatchMode = 'js' | 'full'
export type PageWatchState = 'pending' | 'ok' | 'failed' | 'blocked' | 'waiting'
export type PageChangeSeverity = 'info' | 'low' | 'medium' | 'high'

export interface PageWatch {
  id: string
  asset_id: string
  asset_name?: string
  parent_id?: string
  url: string
  mode: PageWatchMode
  source: 'manual' | 'suggested' | 'derived'
  enabled: boolean
  cadence_hours: number
  ignore_patterns: string[]
  dynamic: boolean
  state: PageWatchState
  last_error?: string
  next_due_at: string
  last_fetched_at?: string
  last_status?: number
  last_changed_at?: string
  changes: number
  scripts: number
  created_at: string
  updated_at: string
}

export interface PageWatchList {
  items: PageWatch[]
  max: number
}

export interface PageSuggestion {
  url: string
  asset_id: string
  asset_name: string
  reason: 'root' | 'login' | 'admin' | 'script'
  mode: PageWatchMode
}

export interface PageScriptRef {
  src?: string
  id: string
  host?: string
  third_party?: boolean
  inline?: boolean
  integrity?: boolean
}

export interface PageChangeSummary {
  scripts_added: number
  scripts_removed: number
  third_party_added: number
  new_third_party_hosts: number
  content_changed: boolean
  urls_added: number
  urls_removed: number
  lines_added: number
  lines_removed: number
}

export interface PageChangeDiff {
  kind: 'html' | 'script' | 'other'
  scripts_added?: PageScriptRef[]
  scripts_removed?: PageScriptRef[]
  new_third_party_hosts?: string[]
  gone_third_party_hosts?: string[]
  hash_from?: string
  hash_to?: string
  size_from: number
  size_to: number
  status_from?: number
  status_to?: number
  urls_added?: string[]
  urls_removed?: string[]
  lines_added?: string[]
  lines_removed?: string[]
  truncated?: boolean
}

export interface PageChange {
  id: string
  watch_id: string
  asset_id: string
  url: string
  parent_id?: string
  parent_url?: string
  detected_at: string
  severity: PageChangeSeverity
  muted: boolean
  summary: PageChangeSummary
  diff?: PageChangeDiff
}

export interface PageChangeList {
  items: PageChange[]
  total: number
}

function useAllowed() {
  const { can } = usePermissions()
  const { moduleIds, isLoading } = useTenantModules()
  const on = !isLoading && moduleIds.includes('attack_surface')
  return {
    read: on && can(Permission.AssetsRead),
    write: on && can(Permission.ScansWrite),
  }
}

/** GET .../watches: the watched URLs in the caller's data scope. */
export function usePageWatches() {
  const { read, write } = useAllowed()
  const { data, error, isLoading, mutate } = useSWR<PageWatchList>(
    read ? PAGE_WATCHES_KEY : null,
    get,
    { revalidateOnFocus: false }
  )
  return {
    watches: data?.items ?? [],
    max: data?.max ?? 200,
    error,
    isLoading,
    mutate,
    canRead: read,
    canWrite: write,
  }
}

/** GET .../suggestions: unwatched URLs worth watching. */
export function usePageSuggestions(enabled: boolean) {
  const { read } = useAllowed()
  const { data, error, isLoading, mutate } = useSWR<{ items: PageSuggestion[] }>(
    read && enabled ? PAGE_SUGGESTIONS_KEY : null,
    get,
    { revalidateOnFocus: false }
  )
  return { suggestions: data?.items ?? [], error, isLoading, mutate }
}

export const PAGE_CHANGES_PAGE_SIZE = 50

export interface PageChangeFilter {
  minSeverity?: PageChangeSeverity | ''
  muted?: boolean
  watchId?: string
}

export function pageChangesKey(f: PageChangeFilter, page: number): string {
  const q = new URLSearchParams()
  if (f.minSeverity) q.set('min_severity', f.minSeverity)
  if (f.muted) q.set('muted', 'true')
  if (f.watchId) q.set('watch_id', f.watchId)
  q.set('page', String(page))
  q.set('per_page', String(PAGE_CHANGES_PAGE_SIZE))
  return `${PAGE_MONITOR_BASE}/changes?${q.toString()}`
}

/** GET .../changes, one page at a time (`loadMore` appends the next). */
export function usePageChanges(f: PageChangeFilter) {
  const { read } = useAllowed()
  const { data, error, isLoading, isValidating, mutate, size, setSize } =
    useSWRInfinite<PageChangeList>((index) => (read ? pageChangesKey(f, index + 1) : null), get, {
      revalidateOnFocus: false,
      revalidateFirstPage: false,
    })
  const changes = (data ?? []).flatMap((p) => p?.items ?? [])
  const total = data?.[0]?.total ?? 0
  return {
    changes,
    total,
    error,
    isLoading,
    mutate,
    hasMore: changes.length < total,
    loadingMore: isValidating && size > (data?.length ?? 0),
    loadMore: () => setSize(size + 1),
  }
}

/** GET .../changes/{id}: one change with its diff. */
export function usePageChange(id: string | null) {
  const { read } = useAllowed()
  const { data, error, isLoading } = useSWR<PageChange>(
    read && id ? `${PAGE_MONITOR_BASE}/changes/${encodeURIComponent(id)}` : null,
    get,
    { revalidateOnFocus: false }
  )
  return { change: data, error, isLoading }
}

export interface PageWatchInput {
  url?: string
  source?: 'manual' | 'suggested'
  enabled?: boolean
  mode?: PageWatchMode
  cadence_hours?: number
  ignore_patterns?: string[]
}

export function createPageWatch(input: PageWatchInput) {
  return post<PageWatch>(PAGE_WATCHES_KEY, input)
}

export function updatePageWatch(id: string, input: PageWatchInput) {
  return put<PageWatch>(`${PAGE_WATCHES_KEY}/${encodeURIComponent(id)}`, input)
}

export function deletePageWatch(id: string) {
  return del(`${PAGE_WATCHES_KEY}/${encodeURIComponent(id)}`)
}
