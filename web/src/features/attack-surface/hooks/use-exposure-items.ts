'use client'

import useSWR from 'swr'
import { get } from '@/lib/api/client'
import { Permission, usePermissions } from '@/lib/permissions'
import {
  exposureAssetGroupsUrl,
  exposureItemStatsUrl,
  exposureItemsUrl,
  type ExposureAssetGroupRow,
  type ExposureItemFilters,
  type ExposureItemRow,
  type ExposureItemStats,
} from '../lib/exposure-items'

interface Page<T> {
  data?: T[]
  total?: number
}

const swrConfig = {
  revalidateOnFocus: false,
  keepPreviousData: true,
  shouldRetryOnError: (error: { statusCode?: number }) =>
    !((error?.statusCode ?? 0) >= 400 && (error?.statusCode ?? 0) < 500),
}

/** The API gate of the view: findings:read and exposures:read. */
function useCanReadExposureItems(): boolean {
  const { can } = usePermissions()
  return can(Permission.FindingsRead) && can(Permission.ExposuresRead)
}

/** One page of exposure items; nothing is fetched without the read permissions. */
export function useExposureItems(
  f: ExposureItemFilters,
  page: { page: number; perPage: number },
  sort: string | undefined,
  enabled = true
) {
  const allowed = useCanReadExposureItems()
  const key = allowed && enabled ? exposureItemsUrl(f, page, sort) : null
  const { data, error, isLoading, mutate } = useSWR<Page<ExposureItemRow>>(
    key,
    (u: string) => get<Page<ExposureItemRow>>(u),
    swrConfig
  )
  return { rows: data?.data ?? [], total: data?.total ?? 0, error, isLoading, mutate }
}

/** One page of the group-by-asset form. */
export function useExposureAssetGroups(
  f: ExposureItemFilters,
  page: { page: number; perPage: number },
  enabled: boolean
) {
  const allowed = useCanReadExposureItems()
  const key = allowed && enabled ? exposureAssetGroupsUrl(f, page) : null
  const { data, error, isLoading, mutate } = useSWR<Page<ExposureAssetGroupRow>>(
    key,
    (u: string) => get<Page<ExposureAssetGroupRow>>(u),
    swrConfig
  )
  return { rows: data?.data ?? [], total: data?.total ?? 0, error, isLoading, mutate }
}

/** Counts by severity, display category and state (the summary strips). */
export function useExposureItemStats(f: ExposureItemFilters) {
  const allowed = useCanReadExposureItems()
  const key = allowed ? exposureItemStatsUrl(f) : null
  return useSWR<ExposureItemStats>(key, (u: string) => get<ExposureItemStats>(u), swrConfig)
}

/** Every exposure of a filter, for the export (bounded). */
export async function fetchAllExposureItems(
  f: ExposureItemFilters,
  sort?: string
): Promise<ExposureItemRow[]> {
  const PER_PAGE = 100
  const MAX_PAGES = 20
  const out: ExposureItemRow[] = []
  for (let page = 1; page <= MAX_PAGES; page++) {
    const res = await get<Page<ExposureItemRow>>(
      exposureItemsUrl(f, { page, perPage: PER_PAGE }, sort)
    )
    const data = res.data ?? []
    out.push(...data)
    if (data.length < PER_PAGE || out.length >= (res.total ?? 0)) break
  }
  return out
}
