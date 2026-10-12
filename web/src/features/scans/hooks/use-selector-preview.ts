'use client'

/**
 * Live preview of the scan's dynamic selectors (RFC-068): for each `*.x` or
 * inventory-mode CIDR, how many assets the inventory holds for it now and the
 * ones seen most recently. One request per selector (at most 10), all in
 * parallel, tenant- and data-scoped by the API.
 */

import { useMemo } from 'react'
import useSWR from 'swr'
import { get } from '@/lib/api/client'
import { useTenant } from '@/context/tenant-provider'
import { Permission, usePermissions } from '@/lib/permissions'
import type { ScanTargetOptions } from '@/lib/api/scan-types'
import { selectorPreviewURL, type TargetSelector } from '../lib/dynamic-targets'

/** Selectors previewed at most. */
export const MAX_PREVIEWED_SELECTORS = 10

interface AssetListPage {
  data?: { name?: string; last_seen?: string }[]
  total?: number
}

export interface SelectorPreview {
  selector: TargetSelector
  /** Assets the inventory holds for the selector now (that the viewer can see). */
  total: number
  /** The most recently seen ones (at most 5). */
  recent: { name: string; lastSeen?: string }[]
}

export function useSelectorPreview(
  selectors: TargetSelector[],
  options: ScanTargetOptions | undefined
) {
  const { currentTenant } = useTenant()
  const { can } = usePermissions()
  const shown = useMemo(() => selectors.slice(0, MAX_PREVIEWED_SELECTORS), [selectors])
  const urls = useMemo(() => shown.map((s) => selectorPreviewURL(s, options)), [shown, options])
  const key =
    currentTenant && can(Permission.AssetsRead) && urls.length > 0
      ? ['selector-preview', ...urls]
      : null
  const { data, isLoading, error } = useSWR<SelectorPreview[]>(
    key,
    async () => {
      const pages = await Promise.all(urls.map((u) => get<AssetListPage>(u)))
      return pages.map((p, i) => ({
        selector: shown[i],
        total: p?.total ?? p?.data?.length ?? 0,
        recent: (p?.data ?? [])
          .filter((a): a is { name: string; last_seen?: string } => typeof a.name === 'string')
          .map((a) => ({ name: a.name, lastSeen: a.last_seen })),
      }))
    },
    { revalidateOnFocus: false, keepPreviousData: true }
  )
  return {
    previews: data ?? [],
    isLoading: key !== null && isLoading,
    error,
    enabled: key !== null,
  }
}
