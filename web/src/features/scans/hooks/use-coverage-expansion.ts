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
  type CoverageLevel,
  type InventoryName,
} from '../lib/coverage-expansion'

/** Roots looked up per scan (each one GET, 100 names). */
export const MAX_COVERAGE_ROOTS = 10

interface AssetListPage {
  data?: { name?: string; properties?: Record<string, unknown> }[]
}

async function loadUnder(roots: string[]): Promise<InventoryName[]> {
  const pages = await Promise.all(
    roots.map((r) =>
      get<AssetListPage>(`/api/v1/assets?${new URLSearchParams({ search: r, per_page: '100' })}`)
    )
  )
  return pages.flatMap((p) =>
    (p?.data ?? [])
      .filter((a): a is { name: string; properties?: Record<string, unknown> } => !!a.name)
      .map((a) => ({ name: a.name, properties: a.properties }))
  )
}

export function useCoverageExpansion(typed: string[], level: CoverageLevel) {
  const { currentTenant } = useTenant()
  const { can } = usePermissions()
  const roots = useMemo(() => domainRoots(typed).slice(0, MAX_COVERAGE_ROOTS), [typed])
  const key =
    level !== 'host' && currentTenant && can(Permission.AssetsRead) && roots.length > 0
      ? ['coverage-expansion', currentTenant.id, ...roots]
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
