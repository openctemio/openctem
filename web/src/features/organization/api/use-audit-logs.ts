/**
 * Audit Log API Hooks
 *
 * SWR hooks for fetching and managing audit logs
 * Note: Tenant is determined from JWT token, not URL path
 */

import useSWR from 'swr'
import { fetcher } from '@/lib/api/client'
import { auditLogEndpoints } from '@/lib/api/endpoints'
import { useTenant } from '@/context/tenant-provider'
import { useTenantModules } from '@/features/integrations/api/use-tenant-modules'
import type {
  AuditLogListResponse,
  AuditStatsResponse,
  AuditLogFilters,
  AuditLog,
} from '../types/audit.types'

// ============================================
// PAGING
// ============================================

/**
 * The audit-log API pages are 1-based (`page=1` is the newest page; a missing
 * or zero page is clamped to 1 by the server). Tables are 0-based
 * (`pageIndex`). Every caller converts through this helper so the two can
 * never be mixed up again: sending `pageIndex` as `page` showed the newest
 * page twice and made the oldest page unreachable.
 */
export function toAuditApiPage(pageIndex: number): number {
  return Number.isFinite(pageIndex) && pageIndex > 0 ? Math.floor(pageIndex) + 1 : 1
}

/** Clamp a caller-supplied 1-based page to the API contract (>= 1). */
function apiPage(page: number): number {
  return Number.isFinite(page) && page >= 1 ? Math.floor(page) : 1
}

// ============================================
// URL BUILDER
// ============================================

function buildAuditLogsUrl(filters?: AuditLogFilters): string {
  const params = new URLSearchParams()

  if (filters?.actor_id) params.append('actor_id', filters.actor_id)
  if (filters?.resource_id) params.append('resource_id', filters.resource_id)
  if (filters?.since) params.append('since', filters.since)
  if (filters?.until) params.append('until', filters.until)
  if (filters?.search) params.append('search', filters.search)
  if (filters?.page !== undefined) params.append('page', apiPage(filters.page).toString())
  if (filters?.per_page) params.append('per_page', filters.per_page.toString())
  if (filters?.sort_by) params.append('sort_by', filters.sort_by)
  if (filters?.sort_order) params.append('sort_order', filters.sort_order)
  if (filters?.exclude_system) params.append('exclude_system', 'true')

  // Array params
  if (filters?.action?.length) {
    filters.action.forEach((a) => params.append('action', a))
  }
  if (filters?.resource_type?.length) {
    filters.resource_type.forEach((rt) => params.append('resource_type', rt))
  }
  if (filters?.result?.length) {
    filters.result.forEach((r) => params.append('result', r))
  }
  if (filters?.severity?.length) {
    filters.severity.forEach((s) => params.append('severity', s))
  }

  const queryString = params.toString()
  return `/api/v1/audit-logs${queryString ? `?${queryString}` : ''}`
}

// ============================================
// FETCH AUDIT LOGS
// ============================================

/**
 * Hook to fetch audit logs with filtering and pagination
 * Requires tenant context and audit module enabled
 */
export function useAuditLogs(filters?: AuditLogFilters) {
  const { currentTenant } = useTenant()
  const { moduleIds, isLoading: modulesLoading } = useTenantModules()
  const url = buildAuditLogsUrl(filters)

  const hasAuditModule = moduleIds.includes('audit')

  // Only fetch if tenant is selected AND audit module is enabled
  const shouldFetch = currentTenant && hasAuditModule && !modulesLoading
  const { data, error, isLoading, mutate } = useSWR<AuditLogListResponse>(
    shouldFetch ? url : null,
    fetcher,
    {
      revalidateOnFocus: false,
      dedupingInterval: 10000, // 10 seconds
    }
  )

  return {
    logs: data?.data ?? [],
    total: data?.total ?? 0,
    page: data?.page ?? 1,
    perPage: data?.per_page ?? 20,
    totalPages: data?.total_pages ?? 0,
    isLoading: shouldFetch ? isLoading : false,
    isError: !!error,
    error,
    mutate,
  }
}

/**
 * Hook to fetch audit log statistics
 * Requires tenant context and audit module enabled
 */
export function useAuditStats() {
  const { currentTenant } = useTenant()
  const { moduleIds, isLoading: modulesLoading } = useTenantModules()

  const hasAuditModule = moduleIds.includes('audit')
  const shouldFetch = currentTenant && hasAuditModule && !modulesLoading

  const { data, error, isLoading, mutate } = useSWR<AuditStatsResponse>(
    shouldFetch ? auditLogEndpoints.stats() : null,
    fetcher,
    {
      revalidateOnFocus: false,
      dedupingInterval: 30000, // 30 seconds
    }
  )

  return {
    stats: data,
    isLoading: shouldFetch ? isLoading : false,
    isError: !!error,
    error,
    mutate,
  }
}

/**
 * Hook to fetch a single audit log by ID
 * Requires tenant context and audit module enabled
 */
export function useAuditLog(id: string | undefined) {
  const { currentTenant } = useTenant()
  const { moduleIds, isLoading: modulesLoading } = useTenantModules()

  const hasAuditModule = moduleIds.includes('audit')
  const shouldFetch = currentTenant && id && hasAuditModule && !modulesLoading

  const { data, error, isLoading, mutate } = useSWR<AuditLog>(
    shouldFetch ? auditLogEndpoints.get(id) : null,
    fetcher,
    {
      revalidateOnFocus: false,
    }
  )

  return {
    log: data,
    isLoading: shouldFetch ? isLoading : false,
    isError: !!error,
    error,
    mutate,
  }
}

/**
 * Hook to fetch audit history for a specific resource
 * Requires tenant context and audit module enabled
 */
export function useResourceAuditHistory(
  resourceType: string | undefined,
  resourceId: string | undefined,
  /** 1-based, like the API. */
  page = 1,
  perPage = 10
) {
  const { currentTenant } = useTenant()
  const { moduleIds, isLoading: modulesLoading } = useTenantModules()

  const hasAuditModule = moduleIds.includes('audit')

  const url =
    resourceType && resourceId
      ? `${auditLogEndpoints.resourceHistory(resourceType, resourceId)}?page=${apiPage(page)}&per_page=${perPage}`
      : null

  const shouldFetch = currentTenant && url && hasAuditModule && !modulesLoading

  const { data, error, isLoading, mutate } = useSWR<AuditLogListResponse>(
    shouldFetch ? url : null,
    fetcher,
    {
      revalidateOnFocus: false,
    }
  )

  return {
    logs: data?.data ?? [],
    total: data?.total ?? 0,
    isLoading: shouldFetch ? isLoading : false,
    isError: !!error,
    error,
    mutate,
  }
}

/**
 * Hook to fetch audit logs for a specific user
 * Requires tenant context and audit module enabled
 */
export function useUserAuditActivity(
  userId: string | undefined,
  /** 1-based, like the API. */
  page = 1,
  perPage = 10
) {
  const { currentTenant } = useTenant()
  const { moduleIds, isLoading: modulesLoading } = useTenantModules()

  const hasAuditModule = moduleIds.includes('audit')

  const url = userId
    ? `${auditLogEndpoints.userActivity(userId)}?page=${apiPage(page)}&per_page=${perPage}`
    : null

  const shouldFetch = currentTenant && url && hasAuditModule && !modulesLoading

  const { data, error, isLoading, mutate } = useSWR<AuditLogListResponse>(
    shouldFetch ? url : null,
    fetcher,
    {
      revalidateOnFocus: false,
    }
  )

  return {
    logs: data?.data ?? [],
    total: data?.total ?? 0,
    isLoading: shouldFetch ? isLoading : false,
    isError: !!error,
    error,
    mutate,
  }
}

// ============================================
// CACHE KEYS
// ============================================

export function getAuditLogsKey(filters?: AuditLogFilters) {
  return buildAuditLogsUrl(filters)
}

export function getAuditStatsKey() {
  return auditLogEndpoints.stats()
}

export function getAuditLogKey(id: string) {
  return auditLogEndpoints.get(id)
}
