'use client'

/**
 * Loads the inventory names under each typed domain (GET /api/v1/assets,
 * tenant- and data-scoped by the server) and expands the scan's targets to
 * the chosen coverage level. See `../lib/coverage-expansion`.
 */

import { useMemo } from 'react'
import useSWR from 'swr'
import { get } from '@/lib/api/client'
import { useTenant } from '@/context/tenant-provider'
import { Permission, usePermissions } from '@/lib/permissions'
import {
  domainRoots,
  expandTargets,
  MAX_EXPANDED_TARGETS,
  type CoverageLevel,
  type InventoryName,
} from '../lib/coverage-expansion'

/** Roots looked up per scan (the API's `under` takes at most 10). */
export const MAX_COVERAGE_ROOTS = 10

/** Pages of 100 names read at most (an expansion adds at most 500 targets). */
const MAX_PAGES = Math.ceil(MAX_EXPANDED_TARGETS / 100)

interface AssetListPage {
  data?: { name?: string; properties?: Record<string, unknown> }[]
  total?: number
}

/** `GET /assets?under=…`: the names equal to or below any of the roots. */
export function coverageURL(roots: string[], page: number): string {
  const params = new URLSearchParams({ under: roots.join(','), per_page: '100' })
  if (page > 1) params.set('page', String(page))
  return `/api/v1/assets?${params}`
}

/**
 * One request for every root (research/81: it used to be one search per
 * root), and more pages only when the inventory holds more names.
 */
async function loadUnder(roots: string[]): Promise<InventoryName[]> {
  const names: InventoryName[] = []
  for (let page = 1; page <= MAX_PAGES; page++) {
    const p = await get<AssetListPage>(coverageURL(roots, page))
    for (const a of p?.data ?? []) {
      if (a.name) names.push({ name: a.name, properties: a.properties })
    }
    if ((p?.data?.length ?? 0) < 100 || names.length >= (p?.total ?? 0)) break
  }
  return names
}

export function useCoverageExpansion(typed: string[], level: CoverageLevel) {
  const { currentTenant } = useTenant()
  const { can } = usePermissions()
  const roots = useMemo(() => domainRoots(typed).slice(0, MAX_COVERAGE_ROOTS), [typed])
  // Only the addresses are listed: subdomains are a *.domain target the API
  // resolves at every run (RFC-068).
  const key =
    level === 'subdomains_ips' && currentTenant && can(Permission.AssetsRead) && roots.length > 0
      ? coverageURL(roots, 1)
      : null
  const { data, isLoading, error } = useSWR<InventoryName[]>(key, () => loadUnder(roots), {
    revalidateOnFocus: false,
    keepPreviousData: true,
  })
  const enabled = key !== null
  const added = useMemo(
    () => (enabled ? expandTargets(typed, level, data ?? []) : []),
    [enabled, typed, level, data]
  )
  return { added, roots, isLoading: enabled && isLoading, error }
}
