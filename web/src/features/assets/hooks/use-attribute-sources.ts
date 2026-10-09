'use client'

import { useState } from 'react'
import useSWR from 'swr'
import { del, get, put } from '@/lib/api/client'
import { usePermissions, Permission } from '@/lib/permissions'
import type {
  AttributeSources,
  AttributeSourcesList,
  ReconciliationPolicy,
  ReconciliationSettings,
  TrackedAttribute,
} from '../lib/attribute-sources'

/** GET /api/v1/assets/{id}/attribute-sources — which source decides each value (RFC-069). */
export function useAttributeSources(assetId: string | null) {
  const { can } = usePermissions()
  const key =
    assetId && can(Permission.AssetsRead) ? `/api/v1/assets/${assetId}/attribute-sources` : null
  const { data, error, isLoading, mutate } = useSWR<AttributeSourcesList>(key, get, {
    revalidateOnFocus: false,
  })
  return { data, error, isLoading, mutate }
}

/** Set-and-lock and release of one attribute (audited, assets:write). */
export function useAttributeLock(assetId: string) {
  const [saving, setSaving] = useState(false)
  const path = (a: TrackedAttribute) => `/api/v1/assets/${assetId}/attribute-sources/${a}/lock`
  const run = async (fn: () => Promise<AttributeSources>) => {
    setSaving(true)
    try {
      return await fn()
    } finally {
      setSaving(false)
    }
  }
  return {
    saving,
    lock: (a: TrackedAttribute, value: string) =>
      run(() => put<AttributeSources>(path(a), { value })),
    release: (a: TrackedAttribute) => run(() => del<AttributeSources>(path(a))),
  }
}

export const RECONCILIATION_SETTINGS_PATH = '/api/v1/organization/settings/asset-reconciliation'

/** The organization's source precedence and TTLs (owner/admin). */
export function useReconciliationSettings(enabled: boolean) {
  const { data, error, isLoading, mutate } = useSWR<ReconciliationSettings>(
    enabled ? RECONCILIATION_SETTINGS_PATH : null,
    get,
    { revalidateOnFocus: false }
  )
  return { data, error, isLoading, mutate }
}

export async function saveReconciliationSettings(
  body: ReconciliationPolicy
): Promise<ReconciliationSettings> {
  return put<ReconciliationSettings>(RECONCILIATION_SETTINGS_PATH, body)
}
