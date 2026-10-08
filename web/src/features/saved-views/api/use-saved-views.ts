'use client'

/**
 * Saved list views (UI style contract D15, API RFC-048 §3.6). A view stores
 * the page's filter (validated by the API on save and on every run) and page
 * state. It is personal, or shared with one of the caller's groups; only its
 * owner edits it, others duplicate it. A view runs as whoever uses it.
 */

import useSWR from 'swr'

import { useTenant } from '@/context/tenant-provider'
import { del, get, post } from '@/lib/api/client'
import { SWR_REFERENCE } from '@/lib/swr-config'

export type SavedViewPage = 'findings'

export interface SavedView {
  id: string
  page: SavedViewPage
  name: string
  description?: string
  filter: Record<string, unknown>
  group_by?: string
  columns?: string[]
  density?: string
  owner_id: string
  owner_name?: string
  group_id?: string
  group_name?: string
  is_owner: boolean
  created_at: string
  updated_at: string
}

export interface SaveViewInput {
  page: SavedViewPage
  name: string
  /** The page's flat query (the API's own params), e.g. "severity=critical&q=log4j". */
  query: string
  group_id?: string
  group_by?: string
}

export const savedViewsKey = (page: SavedViewPage) => `/api/v1/views?page=${page}`

export function useSavedViews(page: SavedViewPage, enabled = true) {
  const { currentTenant } = useTenant()
  const key = currentTenant && enabled ? savedViewsKey(page) : null
  // Reference data: served from cache when the menu shows again; creating,
  // deleting or duplicating a view calls mutate().
  const { data, error, isLoading, mutate } = useSWR<{ data: SavedView[] }>(
    key,
    (url: string) => get<{ data: SavedView[] }>(url),
    SWR_REFERENCE
  )
  return { views: data?.data ?? [], error, isLoading, mutate }
}

export function createSavedView(input: SaveViewInput): Promise<SavedView> {
  return post<SavedView>('/api/v1/views', input)
}

export function deleteSavedView(id: string): Promise<void> {
  return del<void>(`/api/v1/views/${encodeURIComponent(id)}`)
}

export function duplicateSavedView(id: string): Promise<SavedView> {
  return post<SavedView>('/api/v1/views', { from_view_id: id })
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

/** A saved view id in the URL's `view` param (the page also uses `view=verify`). */
export function savedViewId(viewParam: string | null | undefined): string | undefined {
  return viewParam && UUID_RE.test(viewParam) ? viewParam : undefined
}

/** The page params that are not part of a view's filter. */
const PAGE_ONLY = new Set(['page', 'per_page', 'group', 'tab', 'density'])

/**
 * The filter part of a page query string, to save as a view: the API's own
 * params without paging and page-only state. An open saved view stays
 * (`view=<id>`): the API saves its filter with these params on top.
 */
export function viewQueryFromSearch(search: string): string {
  const params = new URLSearchParams(search)
  const out = new URLSearchParams()
  params.forEach((value, key) => {
    if (PAGE_ONLY.has(key)) return
    if (key === 'view' && !savedViewId(value)) return
    out.append(key, value)
  })
  return out.toString()
}
