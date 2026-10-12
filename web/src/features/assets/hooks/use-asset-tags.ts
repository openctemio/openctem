'use client'

import useSWR from 'swr'
import { get } from '@/lib/api/client'
import { useTenant } from '@/context/tenant-provider'
import { usePermissions, Permission } from '@/lib/permissions'

interface TagsResponse {
  tags: string[]
  /** Only with include_system: platform-derived tags (program links). */
  system_tags?: string[]
}

export interface AssetTagsOptions {
  /** Substring search (the API's `q`). */
  q?: string
  /** Also fetch the system tags the caller may see. */
  includeSystem?: boolean
  /** At most this many tags per list (API maximum 100). */
  limit?: number
}

/**
 * The tags of the assets the caller may list, most used first (tenant and
 * data scope are applied by the API). Supports a prefix (autocomplete), a
 * substring search and the system tags (the filter panel).
 */
export function useAssetTags(
  prefix?: string,
  enabled = true,
  types?: string[],
  options: AssetTagsOptions = {}
) {
  const { currentTenant } = useTenant()
  const { can } = usePermissions()
  const canReadAssets = can(Permission.AssetsRead)

  const shouldFetch = enabled && currentTenant && canReadAssets

  const params = new URLSearchParams()
  if (prefix) params.set('prefix', prefix)
  if (options.q) params.set('q', options.q)
  if (options.includeSystem) params.set('include_system', 'true')
  if (options.limit) params.set('limit', String(options.limit))
  if (types && types.length > 0) {
    for (const t of types) params.append('type', t)
  }
  const qs = params.toString()
  const url = qs ? `/api/v1/assets/tags?${qs}` : '/api/v1/assets/tags'

  const { data, error, isLoading } = useSWR<TagsResponse>(
    shouldFetch ? url : null,
    (key: string) => get<TagsResponse>(key),
    {
      revalidateOnFocus: false,
      dedupingInterval: 60000,
      // Typing in a tag search keeps the last list on screen until the next arrives.
      keepPreviousData: true,
    }
  )

  return {
    tags: data?.tags || [],
    systemTags: data?.system_tags || [],
    isLoading: shouldFetch ? isLoading : false,
    error,
  }
}
