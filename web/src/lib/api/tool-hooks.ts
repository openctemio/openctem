/**
 * Tool API Hooks
 *
 * SWR hooks for the organization's view of the tool catalog: one resource,
 * GET /api/v1/tools (platform tools plus its own custom tools), with
 * include= for its settings, the availability from its sensors and run
 * statistics (api tool-availability.md).
 */

'use client'

import useSWR, { type SWRConfiguration } from 'swr'
import useSWRMutation from 'swr/mutation'
import { get, post, put, del, patch } from './client'
import { handleApiError } from './error-handler'
import { useTenant } from '@/context/tenant-provider'
import { toolEndpoints } from './endpoints'
import type {
  Tool,
  ToolView,
  ToolListResponse,
  ToolListFilters,
  CreateToolRequest,
  UpdateToolRequest,
  ToolWithConfig,
  ToolsWithConfigListResponse,
  ToolAvailabilityItem,
  ToolAvailabilityResponse,
  ToolAvailabilityStatus,
} from './tool-types'

// ============================================
// SWR CONFIGURATION
// ============================================

const defaultConfig: SWRConfiguration = {
  revalidateOnFocus: false,
  revalidateOnReconnect: true,
  // Don't retry on client errors (4xx) - only retry on server/network errors
  shouldRetryOnError: (error) => {
    if (error?.statusCode >= 400 && error?.statusCode < 500) {
      return false
    }
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
// FETCHERS
// ============================================

/** The page size the API allows with include=availability or stats. */
const VIEW_PAGE_SIZE = 50
/** Bound on the pages read for one view (2,000 tools: the API's catalog bound). */
const MAX_VIEW_PAGES = 40

/**
 * Every page of a tool list. The pickers and the Tools page need the whole
 * catalog; the API pages it, so the pages are read in turn and joined.
 */
export async function fetchAllTools(url: string): Promise<ToolListResponse> {
  const sep = url.includes('?') ? '&' : '?'
  const first = await get<ToolListResponse>(`${url}${sep}page=1`)
  const items = [...first.items]
  for (let page = 2; page <= Math.min(first.total_pages, MAX_VIEW_PAGES); page++) {
    const next = await get<ToolListResponse>(`${url}${sep}page=${page}`)
    items.push(...next.items)
  }
  return { ...first, items, page: 1, total_pages: 1, per_page: items.length }
}

/** The key of the whole view with settings and availability (one request for both hooks). */
function viewKey(zoneId?: string | null): string {
  return toolEndpoints.list({
    include: 'settings,availability',
    per_page: VIEW_PAGE_SIZE,
    ...(zoneId ? { zone_id: zoneId } : {}),
  })
}

const RUNNABLE: ToolAvailabilityStatus[] = ['ready', 'outdated']

/** The view as the workflow pickers read it: each tool with its settings. */
export function toToolsWithConfig(resp: ToolListResponse): ToolsWithConfigListResponse {
  const items: ToolWithConfig[] = resp.items.map((t: ToolView) => ({
    tool: t,
    effective_config: t.settings?.effective_config ?? {},
    // Left out (no permission) is unknown, never a default: a picker does
    // not offer a tool as enabled when it cannot know.
    is_enabled: t.settings ? t.settings.is_enabled : null,
    is_available: t.availability ? RUNNABLE.includes(t.availability.status) : null,
  }))
  return { items, total: items.length }
}

/** The view as the availability helpers read it: catalog tools and unlisted ones. */
export function toAvailability(resp: ToolListResponse): ToolAvailabilityResponse | undefined {
  if (!resp.availability) return undefined
  const items: ToolAvailabilityItem[] = []
  for (const t of resp.items) {
    if (t.availability) items.push({ ...t.availability, name: t.name, tool: t, in_catalog: true })
  }
  for (const u of resp.availability.unlisted) {
    items.push({ ...u, tool: null, in_catalog: false })
  }
  return {
    items,
    summary: resp.availability.summary,
    zone_id: resp.availability.zone_id,
    computed_at: resp.availability.computed_at,
  }
}

// ============================================
// READ HOOKS
// ============================================

/**
 * One page of the catalog (platform tools plus the organization's custom
 * tools), with the given filters.
 */
export function useTools(filters?: ToolListFilters, config?: SWRConfiguration) {
  const { currentTenant } = useTenant()

  const key = currentTenant ? toolEndpoints.list(filters) : null

  return useSWR<ToolListResponse>(key, (url: string) => get<ToolListResponse>(url), {
    ...defaultConfig,
    ...config,
  })
}

/**
 * Every tool with the organization's settings and whether a scan job can be
 * dispatched now: the workflow pickers' list.
 */
export function useToolsWithConfig(config?: SWRConfiguration) {
  const { currentTenant } = useTenant()
  const swr = useSWR<ToolListResponse>(currentTenant ? viewKey() : null, fetchAllTools, {
    ...defaultConfig,
    ...config,
  })
  return { ...swr, data: swr.data ? toToolsWithConfig(swr.data) : undefined }
}

/**
 * Tool availability: every catalog tool plus every tool the organization's
 * sensors report, with the sensors that have it, their versions and a
 * derived status. The one source the Tools page, the scan and workflow tool
 * pickers and the sensor detail read. zoneId limits it to the sensors of one
 * scan zone. Undefined data when the caller may not read the availability
 * (the API leaves it out).
 */
export function useToolAvailability(zoneId?: string | null, config?: SWRConfiguration) {
  const { currentTenant } = useTenant()
  const swr = useSWR<ToolListResponse>(currentTenant ? viewKey(zoneId) : null, fetchAllTools, {
    ...defaultConfig,
    ...config,
  })
  return { ...swr, data: swr.data ? toAvailability(swr.data) : undefined }
}

// ============================================
// CUSTOM TOOLS (the organization's own)
// ============================================

/**
 * Create a custom tool
 */
export function useCreateCustomTool() {
  const { currentTenant } = useTenant()

  return useSWRMutation(
    currentTenant ? toolEndpoints.create() : null,
    async (url: string, { arg }: { arg: CreateToolRequest }) => {
      return post<Tool>(url, arg)
    }
  )
}

/**
 * Update a custom tool
 */
export function useUpdateCustomTool(toolId: string) {
  const { currentTenant } = useTenant()

  return useSWRMutation(
    currentTenant && toolId ? toolEndpoints.update(toolId) : null,
    async (url: string, { arg }: { arg: UpdateToolRequest }) => {
      return put<Tool>(url, arg)
    }
  )
}

/**
 * Delete a custom tool
 */
export function useDeleteCustomTool(toolId: string) {
  const { currentTenant } = useTenant()

  return useSWRMutation(
    currentTenant && toolId ? toolEndpoints.delete(toolId) : null,
    async (url: string) => {
      return del<void>(url)
    }
  )
}

// ============================================
// SETTINGS (the organization's switch and overrides)
// ============================================

function useSwitchTool(isEnabled: boolean) {
  const { currentTenant } = useTenant()

  return useSWRMutation(
    currentTenant ? `${toolEndpoints.bulkSettings()}#${isEnabled ? 'on' : 'off'}` : null,
    async (_key: string, { arg: toolId }: { arg: string }) => {
      return patch<void>(toolEndpoints.bulkSettings(), {
        tool_ids: [toolId],
        is_enabled: isEnabled,
      })
    }
  )
}

/**
 * Switch one tool on for the current organization (its own setting; the
 * platform catalog is not changed).
 *
 * Usage: const { trigger } = useEnableTool(); await trigger(toolId);
 */
export function useEnableTool() {
  return useSwitchTool(true)
}

/**
 * Switch one tool off for the current organization.
 *
 * Usage: const { trigger } = useDisableTool(); await trigger(toolId);
 */
export function useDisableTool() {
  return useSwitchTool(false)
}

// ============================================
// CACHE UTILITIES
// ============================================

/**
 * Invalidate every tool read (the list, the view with settings and
 * availability, single tools).
 */
export async function invalidateToolsCache() {
  const { mutate } = await import('swr')
  await mutate((key) => typeof key === 'string' && key.startsWith('/api/v1/tools'), undefined, {
    revalidate: true,
  })
}
