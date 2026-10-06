/**
 * Scan freeze window hooks: /api/v1/scan-freeze-windows. Tenant from the
 * session; reads need scans:read, writes sensors:zones:write / delete.
 */

'use client'

import useSWR, { type SWRConfiguration } from 'swr'
import { get, post, patch, del } from '@/lib/api/client'
import { useTenant } from '@/context/tenant-provider'
import type {
  CreateFreezeWindowRequest,
  FreezeWindow,
  FreezeWindowList,
  UpdateFreezeWindowRequest,
} from '../types'

export const FREEZE_BASE = '/api/v1/scan-freeze-windows'

/** Which windows a list shows. */
export interface FreezeWindowFilter {
  /** One zone's windows. */
  zoneId?: string
  /** Only the windows that freeze the whole organization. */
  tenantWide?: boolean
}

/** The URL of a window listing; exported for tests. */
export function freezeWindowsURL(f: FreezeWindowFilter = {}): string {
  const q = new URLSearchParams()
  if (f.zoneId) q.set('scan_zone_id', f.zoneId)
  else if (f.tenantWide) q.set('scope', 'tenant')
  const s = q.toString()
  return s ? `${FREEZE_BASE}?${s}` : FREEZE_BASE
}

const defaultConfig: SWRConfiguration = {
  revalidateOnFocus: false,
  shouldRetryOnError: (error) => !(error?.statusCode >= 400 && error?.statusCode < 500),
  errorRetryCount: 2,
}

/**
 * The tenant's freeze windows. Pass `enabled: false` when the caller cannot
 * read scans, so no request (and no 403) is made. Active state is computed
 * by the server at read time, so lists refresh every minute.
 */
export function useFreezeWindows(filter: FreezeWindowFilter = {}, enabled = true) {
  const { currentTenant } = useTenant()
  const key = currentTenant && enabled ? freezeWindowsURL(filter) : null
  return useSWR<FreezeWindowList>(key, (url: string) => get<FreezeWindowList>(url), {
    ...defaultConfig,
    refreshInterval: 60_000,
  })
}

/** Revalidates every freeze window request. */
export async function invalidateFreezeWindowsCache() {
  const { mutate } = await import('swr')
  await mutate((key) => typeof key === 'string' && key.startsWith(FREEZE_BASE), undefined, {
    revalidate: true,
  })
}

export function createFreezeWindow(body: CreateFreezeWindowRequest) {
  return post<FreezeWindow>(FREEZE_BASE, body)
}

export function updateFreezeWindow(id: string, body: UpdateFreezeWindowRequest) {
  return patch<FreezeWindow>(`${FREEZE_BASE}/${id}`, body)
}

export function deleteFreezeWindow(id: string) {
  return del<void>(`${FREEZE_BASE}/${id}`)
}
