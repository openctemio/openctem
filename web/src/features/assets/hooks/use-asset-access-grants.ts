'use client'

import useSWR from 'swr'
import { get, post, del } from '@/lib/api/client'
import { endpoints } from '@/lib/api/endpoints'
import { usePermissions, Permission } from '@/lib/permissions'
import type { components } from '@/lib/api/generated/api.types'

type BackendGrant = components['schemas']['internal_infra_http_handler.AssetAccessGrantResponse']
type BackendGrantList =
  components['schemas']['internal_infra_http_handler.AssetAccessGrantListResponse']

/** An explicit per-user data-scope grant on one asset. */
export interface AssetAccessGrant {
  id: string
  userId: string
  userName?: string
  userEmail?: string
  /** `migration`: created in 2026-10 from the user's former ownership-based access. */
  source: 'manual' | 'migration'
  grantedByName?: string
  grantedAt: string
}

function toGrant(g: BackendGrant): AssetAccessGrant {
  return {
    id: g.id ?? '',
    userId: g.user_id ?? '',
    userName: g.user_name || undefined,
    userEmail: g.user_email || undefined,
    source: g.source === 'migration' ? 'migration' : 'manual',
    grantedByName: g.granted_by_name || undefined,
    grantedAt: g.granted_at ?? '',
  }
}

/** Lists an asset's explicit access grants (needs team:groups:read). */
export function useAssetAccessGrants(assetId: string | null) {
  const { can } = usePermissions()
  const shouldFetch = !!assetId && can(Permission.GroupsRead)
  const { data, error, isLoading, mutate } = useSWR<BackendGrantList>(
    shouldFetch ? endpoints.assets.listAccessGrants(assetId) : null,
    (url: string) => get<BackendGrantList>(url)
  )
  return {
    grants: (data?.data ?? []).map(toGrant),
    isLoading: shouldFetch ? isLoading : false,
    error,
    mutate,
  }
}

export async function createAssetAccessGrant(assetId: string, userId: string): Promise<void> {
  await post(endpoints.assets.createAccessGrant(assetId), { user_id: userId })
}

export async function deleteAssetAccessGrant(assetId: string, grantId: string): Promise<void> {
  await del(endpoints.assets.deleteAccessGrant(assetId, grantId))
}
