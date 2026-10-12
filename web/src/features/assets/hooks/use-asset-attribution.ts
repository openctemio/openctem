'use client'

import { useState } from 'react'
import useSWR from 'swr'
import { get, put } from '@/lib/api/client'
import { usePermissions, Permission } from '@/lib/permissions'
import type { AssetAttribution, AttributionDecision } from '../lib/attribution'

/** GET /api/v1/assets/{id}/attribution — why the asset is believed to be ours. */
export function useAssetAttribution(assetId: string | null) {
  const { can } = usePermissions()
  const key = assetId && can(Permission.AssetsRead) ? `/api/v1/assets/${assetId}/attribution` : null
  const { data, error, isLoading, mutate } = useSWR<AssetAttribution>(key, get, {
    revalidateOnFocus: false,
  })
  return { attribution: data, error, isLoading, mutate }
}

/** PUT /api/v1/assets/{id}/attribution — a person's decision (audited). */
export function useDecideAttribution(assetId: string) {
  const [saving, setSaving] = useState(false)
  const decide = async (state: AttributionDecision) => {
    setSaving(true)
    try {
      return await put<AssetAttribution>(`/api/v1/assets/${assetId}/attribution`, { state })
    } finally {
      setSaving(false)
    }
  }
  return { decide, saving }
}
