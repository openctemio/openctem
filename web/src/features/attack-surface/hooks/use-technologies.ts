'use client'

import useSWR from 'swr'
import { get } from '@/lib/api/client'
import { Permission, usePermissions } from '@/lib/permissions'
import {
  technologiesUrl,
  technologyStatsUrl,
  type TechnologyFilters,
  type TechnologyRow,
  type TechnologyStats,
} from '../lib/technologies'

interface TechnologyPage {
  data?: TechnologyRow[]
  total?: number
}

const swrConfig = {
  revalidateOnFocus: false,
  keepPreviousData: true,
  shouldRetryOnError: (error: { statusCode?: number }) =>
    !((error?.statusCode ?? 0) >= 400 && (error?.statusCode ?? 0) < 500),
}

/** One page of the Technologies list; nothing is fetched without assets:read. */
export function useTechnologies(
  f: TechnologyFilters,
  page: { page: number; perPage: number },
  sort?: string
) {
  const { can } = usePermissions()
  const key = can(Permission.AssetsRead) ? technologiesUrl(f, page, sort) : null
  const { data, error, isLoading, mutate } = useSWR<TechnologyPage>(
    key,
    (u: string) => get<TechnologyPage>(u),
    swrConfig
  )
  return { rows: data?.data ?? [], total: data?.total ?? 0, error, isLoading, mutate }
}

/** Counts for the summary strip (search and category apply, toggles do not). */
export function useTechnologyStats(f: TechnologyFilters) {
  const { can } = usePermissions()
  const key = can(Permission.AssetsRead) ? technologyStatsUrl(f) : null
  return useSWR<TechnologyStats>(key, (u: string) => get<TechnologyStats>(u), swrConfig)
}

/** Every technology version of a filter, for the export (bounded). */
export async function fetchAllTechnologies(
  f: TechnologyFilters,
  sort?: string
): Promise<TechnologyRow[]> {
  const PER_PAGE = 100
  const MAX_PAGES = 20
  const out: TechnologyRow[] = []
  for (let page = 1; page <= MAX_PAGES; page++) {
    const res = await get<TechnologyPage>(technologiesUrl(f, { page, perPage: PER_PAGE }, sort))
    const data = res.data ?? []
    out.push(...data)
    if (data.length < PER_PAGE || out.length >= (res.total ?? 0)) break
  }
  return out
}
