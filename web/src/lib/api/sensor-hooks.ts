/**
 * Sensor API Hooks
 *
 * SWR hooks for Sensor Management
 */

'use client'

import { useMemo, useRef } from 'react'
import useSWR, { type SWRConfiguration } from 'swr'
import useSWRMutation from 'swr/mutation'
import useSWRInfinite from 'swr/infinite'
import { get, post, put, del } from './client'
import { handleApiError } from './error-handler'
import { useTenant } from '@/context/tenant-provider'
import { sensorEndpoints } from './endpoints'
import type {
  Sensor,
  SensorListResponse,
  SensorListFilters,
  CreateSensorRequest,
  CreateSensorResponse,
  UpdateSensorRequest,
  RegenerateAPIKeyResponse,
  AvailableCapabilitiesResponse,
  SensorCommandListResponse,
  SensorActivityCategory,
  SensorActivityItem,
  SensorActivityResponse,
  SensorManifestListResponse,
  SensorConfigReport,
  SensorHeartbeatHistoryResponse,
  SensorProduct,
  SensorSdkStatus,
} from './sensor-types'

// ============================================
// SWR CONFIGURATION
// ============================================

/**
 * For reads whose failure is shown in place (an ErrorState or inline text),
 * or that poll: no toast. A no-op, not `undefined`: SWR keeps the key and
 * calls `onError` unconditionally, so `undefined` throws inside its retry path.
 */
const silentOnError = () => {}

const defaultConfig: SWRConfiguration = {
  revalidateOnFocus: false,
  revalidateOnReconnect: true,
  // Don't retry on client errors (4xx) - only retry on server/network errors
  shouldRetryOnError: (error) => {
    // Don't retry on 4xx errors (client errors like 403, 404, etc.)
    if (error?.statusCode >= 400 && error?.statusCode < 500) {
      return false
    }
    // Retry on 5xx or network errors
    return true
  },
  errorRetryCount: 3,
  errorRetryInterval: 1000,
  dedupingInterval: 2000,
  onError: (error) => {
    handleApiError(error, {
      showToast: true,
      logError: true,
    })
  },
}

// ============================================
// CACHE KEYS
// ============================================

export const sensorKeys = {
  all: ['sensors'] as const,
  lists: () => [...sensorKeys.all, 'list'] as const,
  list: (filters?: SensorListFilters) => [...sensorKeys.lists(), filters] as const,
  details: () => [...sensorKeys.all, 'detail'] as const,
  detail: (id: string) => [...sensorKeys.details(), id] as const,
  availableCapabilities: (includePlatform: boolean = true) =>
    [...sensorKeys.all, 'available-capabilities', includePlatform] as const,
}

// ============================================
// FETCHER FUNCTIONS
// ============================================

async function fetchSensors(url: string): Promise<SensorListResponse> {
  return get<SensorListResponse>(url)
}

async function fetchSensor(url: string): Promise<Sensor> {
  return get<Sensor>(url)
}

async function fetchAvailableCapabilities(url: string): Promise<AvailableCapabilitiesResponse> {
  return get<AvailableCapabilitiesResponse>(url)
}

// ============================================
// SENSOR HOOKS
// ============================================

/** The API's largest page (MaxPerPage). */
export const SENSOR_PAGE_SIZE = 100
/** Safety stop for fetchAllSensorPages: 5,000 sensors. */
const MAX_SENSOR_PAGES = 50

/**
 * Reads every page of GET /sensors. The sensors page groups, filters and
 * counts the whole fleet on the client (the state ladder depends on the
 * current time), and a fleet is small, so it loads all of it rather than
 * showing page 1 of a list the toolbar then filters. The page used to send
 * page_size, which the API ignores, so it only ever saw the first 20.
 */
export async function fetchAllSensorPages(
  getPage: (page: number) => Promise<SensorListResponse>
): Promise<SensorListResponse> {
  const items: Sensor[] = []
  let total = 0
  for (let page = 1; page <= MAX_SENSOR_PAGES; page++) {
    const res = await getPage(page)
    const batch = res.items ?? []
    items.push(...batch)
    total = res.total ?? items.length
    if (batch.length < SENSOR_PAGE_SIZE || items.length >= total) break
  }
  return { items, total: Math.max(total, items.length), page: 1, per_page: items.length }
}

/** Refresh interval for the live sensors view (list, stats and the open sensor). */
export const SENSOR_REFRESH_MS = 15_000

/** GET /sensors?changed_since= (poll mode): the stats and only the sensors that changed. */
export interface SensorFleetChanges extends SensorListResponse {
  /** Every sensor of the fleet (true) or only those changed since the cursor. */
  full?: boolean
  /** Sent as changed_since on the next poll; absent for a very large fleet. */
  cursor?: string
  stats?: TenantSensorStats
}

/** The fleet with the stats that came with it. */
export type SensorFleet = SensorListResponse & { stats?: TenantSensorStats; cursor?: string }

/**
 * Applies a poll answer to the fleet the page holds: a full answer replaces
 * it, a partial one replaces the sensors it carries and keeps the others in
 * place. The fleet's membership is unchanged in a partial answer (the API
 * answers in full when a sensor was added or removed); undefined when a
 * partial answer arrives with no fleet to apply it to.
 */
export function applySensorChanges(
  prev: SensorFleet | undefined,
  res: SensorFleetChanges
): SensorFleet | undefined {
  const items = res.items ?? []
  if (res.full !== false) {
    return {
      items,
      total: res.total ?? items.length,
      page: 1,
      per_page: items.length,
      stats: res.stats,
      cursor: res.cursor,
    }
  }
  if (!prev) return undefined
  const changed = new Map(items.map((s) => [s.id, s]))
  const merged = prev.items.map((s) => changed.get(s.id) ?? s)
  return {
    items: changed.size > 0 ? merged : prev.items,
    total: res.total ?? merged.length,
    page: 1,
    per_page: merged.length,
    stats: res.stats ?? prev.stats,
    cursor: res.cursor,
  }
}

/**
 * Reads the fleet in poll mode: the previous answer's cursor in, the changed
 * sensors and the stats out (one request per refresh, whatever the fleet
 * size). Against an API without poll mode (no `full` in the answer) it reads
 * every page as before.
 */
export async function fetchSensorFleet(
  getChanges: (cursor: string) => Promise<SensorFleetChanges>,
  getPage: (page: number) => Promise<SensorListResponse>,
  prev: SensorFleet | undefined
): Promise<SensorFleet> {
  const res = await getChanges(prev?.cursor ?? '')
  if (typeof res.full !== 'boolean') return fetchAllSensorPages(getPage)
  const next = applySensorChanges(prev, res)
  if (next) return next
  // A partial answer without a fleet to apply it to: start over.
  const snapshot = applySensorChanges(undefined, await getChanges(''))
  return snapshot ?? fetchAllSensorPages(getPage)
}

/**
 * The tenant's whole fleet, refreshed every 15s while the tab is visible,
 * with the fleet stats (`data.stats`) from the same request: each refresh
 * transfers only the sensors whose answer changed.
 */
export function useAllSensors(config?: SWRConfiguration, enabled = true) {
  const { currentTenant } = useTenant()
  const key = currentTenant && enabled ? sensorEndpoints.list({ per_page: SENSOR_PAGE_SIZE }) : null
  // The fleet the last answer built, per organization (the cursor is its own).
  const held = useRef<{ tenant?: string; fleet?: SensorFleet }>({})
  return useSWR<SensorFleet>(
    key,
    async () => {
      const tenant = currentTenant?.id
      const prev = held.current.tenant === tenant ? held.current.fleet : undefined
      const fleet = await fetchSensorFleet(
        (cursor) =>
          get<SensorFleetChanges>(
            `${sensorEndpoints.list()}?changed_since=${encodeURIComponent(cursor)}`
          ),
        (page) =>
          get<SensorListResponse>(sensorEndpoints.list({ per_page: SENSOR_PAGE_SIZE, page })),
        prev
      )
      held.current = { tenant, fleet }
      return fleet
    },
    {
      ...defaultConfig,
      // Polled every 15 s: the page shows an ErrorState, never a toast per poll.
      onError: silentOnError,
      refreshInterval: SENSOR_REFRESH_MS,
      ...config,
    }
  )
}

/**
 * Fetch one page of sensors
 */
export function useSensors(filters?: SensorListFilters, config?: SWRConfiguration) {
  const { currentTenant } = useTenant()

  const key = currentTenant ? sensorEndpoints.list(filters) : null

  return useSWR<SensorListResponse>(key, fetchSensors, {
    ...defaultConfig,
    ...config,
  })
}

/**
 * Tenant-wide aggregated sensor stats from `/api/v1/sensors/stats`.
 *
 * Use this for the sensors page stat cards instead of computing
 * `sensors.filter(...).length` from a paginated list — that pattern undercounts
 * once a tenant has more than one page of sensors (the default page size is 20).
 *
 * This hook does NOT depend on filters/pagination so it stays stable when the
 * user filters the table by status / health / search.
 */
export interface TenantSensorStats {
  total: number
  by_status: Record<string, number>
  by_health: Record<string, number>
  by_type: Record<string, number>
  by_execution_mode: Record<string, number>
  active_jobs: number
  online_active: number
  // Fleet summary (newer APIs): the same population GET /sensors lists.
  by_state?: Record<string, number>
  by_version_status?: Record<string, number>
  needs_attention?: number
  can_take_jobs?: number
  jobs_running?: number
  job_slots?: number
  /** The sensor products the platform knows, each with its release line. */
  products?: SensorProduct[]
  /** State ladder thresholds. */
  online_window_seconds?: number
  offline_after_seconds?: number
  /** The newest SDK release (informational) and the releases with an advisory. */
  sdk_latest_version?: string
  sdk_advisories?: string[]
  /** Sensors per normalized SDK version ("v0.9.0", or "unknown"). */
  by_sdk_version?: Record<string, number>
  by_sdk_status?: Partial<Record<SensorSdkStatus, number>>
}

/**
 * GET /sensors/stats. The sensors page takes the stats from the fleet poll
 * (`useAllSensors().data.stats`) and passes `enabled: false` once it has them.
 */
export function useTenantSensorStats(config?: SWRConfiguration, enabled = true) {
  const { currentTenant } = useTenant()
  const key = currentTenant && enabled ? sensorEndpoints.tenantStats() : null
  return useSWR<TenantSensorStats>(key, (url: string) => get<TenantSensorStats>(url), {
    ...defaultConfig,
    onError: silentOnError,
    dedupingInterval: 5000,
    refreshInterval: SENSOR_REFRESH_MS,
    ...config,
  })
}

/**
 * The latest jobs dispatched to a sensor, refreshed with the drawer. Pass
 * `enabled: false` without sensors:commands:read (no request, no 403 toast).
 */
export function useSensorCommands(sensorId: string | null, enabled = true) {
  const { currentTenant } = useTenant()
  const key = currentTenant && sensorId && enabled ? sensorEndpoints.commands(sensorId) : null
  return useSWR<SensorCommandListResponse>(
    key,
    (url: string) => get<SensorCommandListResponse>(url),
    { ...defaultConfig, onError: silentOnError, refreshInterval: SENSOR_REFRESH_MS }
  )
}

/**
 * A sensor's manifest versions, most recently current first (RFC-033). The
 * first item with `current` is the current manifest. Errors are shown in
 * place (no toast).
 */
export function useSensorManifests(sensorId: string | null, enabled = true) {
  const { currentTenant } = useTenant()
  const key = currentTenant && sensorId && enabled ? sensorEndpoints.manifests(sensorId) : null
  return useSWR<SensorManifestListResponse>(
    key,
    (url: string) => get<SensorManifestListResponse>(url),
    {
      ...defaultConfig,
      onError: silentOnError,
      refreshInterval: SENSOR_REFRESH_MS * 2,
    }
  )
}

/**
 * A sensor's setup report (GET /sensors/{id}/config-report): the checks the
 * sensor ran on itself, explained by the platform catalog. Errors are shown
 * in place (no toast).
 */
export function useSensorConfigReport(sensorId: string | null, enabled = true) {
  const { currentTenant } = useTenant()
  const key = currentTenant && sensorId && enabled ? sensorEndpoints.configReport(sensorId) : null
  return useSWR<SensorConfigReport>(key, (url: string) => get<SensorConfigReport>(url), {
    ...defaultConfig,
    onError: silentOnError,
    refreshInterval: SENSOR_REFRESH_MS * 2,
  })
}

/**
 * A sensor's heartbeat history (GET /sensors/{id}/heartbeat-history): the
 * last 24 h in 15-minute buckets, for the Control channel sparkline. Errors
 * are shown in place (no toast).
 */
export function useSensorHeartbeatHistory(sensorId: string | null, enabled = true) {
  const { currentTenant } = useTenant()
  const key =
    currentTenant && sensorId && enabled ? sensorEndpoints.heartbeatHistory(sensorId) : null
  return useSWR<SensorHeartbeatHistoryResponse>(
    key,
    (url: string) => get<SensorHeartbeatHistoryResponse>(url),
    {
      ...defaultConfig,
      onError: silentOnError,
      // A bucket is 15 minutes: a minute is fresh enough.
      refreshInterval: 60_000,
    }
  )
}

/** Default page size of a sensor's activity timeline (the API's default). */
export const SENSOR_ACTIVITY_PAGE_SIZE = 30

/**
 * A sensor's activity timeline (GET /sensors/{id}/activity), newest first,
 * one cursor page at a time: `loadMore()` appends the next page. Changing
 * `types` starts over from the newest. Errors are shown in place (no toast).
 */
export function useSensorActivity(
  sensorId: string | null,
  types: SensorActivityCategory[] = [],
  options: { limit?: number; refreshInterval?: number } = {}
) {
  const { currentTenant } = useTenant()
  const { limit = SENSOR_ACTIVITY_PAGE_SIZE, refreshInterval = SENSOR_REFRESH_MS * 2 } = options
  const enabled = !!currentTenant && !!sensorId
  const swr = useSWRInfinite<SensorActivityResponse>(
    (index, previous: SensorActivityResponse | null) => {
      if (!enabled || !sensorId) return null
      if (index === 0) return sensorEndpoints.activity(sensorId, { types, limit })
      if (!previous?.next_cursor) return null
      return sensorEndpoints.activity(sensorId, { types, limit, cursor: previous.next_cursor })
    },
    (url: string) => get<SensorActivityResponse>(url),
    {
      revalidateOnFocus: false,
      shouldRetryOnError: defaultConfig.shouldRetryOnError,
      errorRetryCount: 2,
      refreshInterval,
    }
  )
  const pages = useMemo(() => swr.data ?? [], [swr.data])
  const items = useMemo(() => {
    const out: SensorActivityItem[] = []
    const seen = new Set<string>()
    for (const p of pages) {
      for (const it of p.items ?? []) {
        // A refresh can shift a coalesced row across a page edge; show it once.
        if (seen.has(it.id)) continue
        seen.add(it.id)
        out.push(it)
      }
    }
    return out
  }, [pages])
  const last = pages[pages.length - 1]
  const hasMore = !!last?.next_cursor
  const isLoadingMore =
    swr.size > 0 && pages.length > 0 && typeof swr.data?.[swr.size - 1] === 'undefined'
  return {
    items,
    /** false when any page says administrator actions were left out. */
    auditIncluded: pages.length === 0 ? true : pages.every((p) => p.audit_included !== false),
    hasMore,
    isLoading: enabled && !swr.data && !swr.error,
    isLoadingMore,
    error: swr.error as unknown,
    loadMore: () => swr.setSize(swr.size + 1),
    retry: () => swr.mutate(),
  }
}

/**
 * Fetch a single sensor by ID
 */
export function useSensor(sensorId: string | null, config?: SWRConfiguration) {
  const { currentTenant } = useTenant()

  const key = currentTenant && sensorId ? sensorEndpoints.get(sensorId) : null

  return useSWR<Sensor>(key, fetchSensor, {
    ...defaultConfig,
    ...config,
  })
}

/**
 * Fetch available capabilities for the current tenant.
 * Returns unique capability names from all sensors accessible to the tenant:
 * - Tenant's own sensors (active + online)
 * - Platform sensors (if includePlatform=true, which is default)
 *
 * Use case: Determine what capabilities a tenant can use based on their available sensors.
 * Example: If platform sensors have capabilities A, B, C and tenant adds a sensor with capability D,
 * the tenant will see they have access to capabilities A, B, C, D.
 *
 * @param includePlatform - Whether to include platform sensors' capabilities (default: true)
 * @param config - SWR configuration options
 */
export function useAvailableCapabilities(
  includePlatform: boolean = true,
  config?: SWRConfiguration
) {
  const { currentTenant } = useTenant()

  const key = currentTenant ? sensorEndpoints.availableCapabilities(includePlatform) : null

  return useSWR<AvailableCapabilitiesResponse>(key, fetchAvailableCapabilities, {
    ...defaultConfig,
    ...config,
  })
}

// ============================================
// MUTATION HOOKS
// ============================================
//
// Hooks that act on one existing sensor take its id when they are
// triggered (`trigger(sensor.id)`), not when the hook is created. A row
// action sets the selection and triggers in the same handler, before React
// re-renders, so a hook bound to the selection would still point at the
// previous sensor (or at none at all).

/**
 * Create a new sensor
 */
export function useCreateSensor() {
  const { currentTenant } = useTenant()

  return useSWRMutation(
    currentTenant ? sensorEndpoints.create() : null,
    async (url: string, { arg }: { arg: CreateSensorRequest }) => {
      return post<CreateSensorResponse>(url, arg)
    }
  )
}

/**
 * Update a sensor
 */
export function useUpdateSensor(sensorId: string) {
  const { currentTenant } = useTenant()

  return useSWRMutation(
    currentTenant && sensorId ? sensorEndpoints.update(sensorId) : null,
    async (url: string, { arg }: { arg: UpdateSensorRequest }) => {
      return put<Sensor>(url, arg)
    }
  )
}

/**
 * Delete a sensor
 */
export function useDeleteSensor() {
  const { currentTenant } = useTenant()

  return useSWRMutation(
    currentTenant ? 'sensor-delete' : null,
    async (_key: string, { arg: sensorId }: { arg: string }) => {
      return del<void>(sensorEndpoints.delete(sensorId))
    }
  )
}

/**
 * Delete multiple sensors (bulk delete)
 */
export function useBulkDeleteSensors() {
  const { currentTenant } = useTenant()

  return useSWRMutation(
    currentTenant ? 'bulk-delete-sensors' : null,
    async (_key: string, { arg: sensorIds }: { arg: string[] }) => {
      // Delete sensors sequentially to avoid overwhelming the server
      const results: { id: string; success: boolean; error?: string }[] = []

      for (const id of sensorIds) {
        try {
          await del<void>(sensorEndpoints.delete(id))
          results.push({ id, success: true })
        } catch (error) {
          results.push({
            id,
            success: false,
            error: error instanceof Error ? error.message : 'Unknown error',
          })
        }
      }

      return results
    }
  )
}

/**
 * Regenerate sensor API key
 */
export function useRegenerateSensorKey() {
  const { currentTenant } = useTenant()

  return useSWRMutation(
    currentTenant ? 'sensor-regenerate-key' : null,
    async (_key: string, { arg: sensorId }: { arg: string }) => {
      return post<RegenerateAPIKeyResponse>(sensorEndpoints.regenerateKey(sensorId), {})
    },
    {
      // Don't revalidate other SWR hooks after mutation
      // We'll manually invalidate when user closes the dialog
      revalidate: false,
      populateCache: false,
    }
  )
}

/**
 * Activate a sensor (set status to active)
 */
export function useActivateSensor() {
  const { currentTenant } = useTenant()

  return useSWRMutation(
    currentTenant ? 'sensor-activate' : null,
    async (_key: string, { arg: sensorId }: { arg: string }) => {
      return post<Sensor>(sensorEndpoints.activate(sensorId), {})
    }
  )
}

/**
 * Deactivate a sensor (set status to disabled)
 */
export function useDeactivateSensor() {
  const { currentTenant } = useTenant()

  return useSWRMutation(
    currentTenant ? 'sensor-deactivate' : null,
    async (_key: string, { arg: sensorId }: { arg: string }) => {
      return post<Sensor>(sensorEndpoints.deactivate(sensorId), {})
    }
  )
}

/**
 * Revoke a sensor (permanently revoke access)
 */
export function useRevokeSensor() {
  const { currentTenant } = useTenant()

  return useSWRMutation(
    currentTenant ? 'sensor-revoke' : null,
    async (_key: string, { arg: sensorId }: { arg: string }) => {
      return post<Sensor>(sensorEndpoints.revoke(sensorId), {})
    }
  )
}

// ============================================
// CACHE UTILITIES
// ============================================

/**
 * Revalidate every sensors request (list, stats, drawer, commands). The data
 * on screen stays until the fresh response arrives, so the table does not
 * flash a skeleton.
 */
export async function invalidateSensorsCache() {
  const { mutate } = await import('swr')
  await mutate((key) => typeof key === 'string' && key.includes('/api/v1/sensors'))
}
