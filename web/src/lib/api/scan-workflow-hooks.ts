/**
 * Workflow API Hooks
 *
 * SWR hooks for Workflow Management (Workflow Orchestration)
 */

'use client'

import useSWR, { type SWRConfiguration } from 'swr'
import useSWRMutation from 'swr/mutation'
import { get, post, put, del } from './client'
import { handleApiError } from './error-handler'
import { useTenant } from '@/context/tenant-provider'
import { scanWorkflowEndpoints, scanRunEndpoints, scanManagementEndpoints } from './endpoints'
import type {
  ScanWorkflow,
  ScanWorkflowListResponse,
  ScanWorkflowListFilters,
  ScanRun,
  ScanRunListResponse,
  ScanRunListFilters,
  ScanWorkflowStep,
  CreateScanWorkflowRequest,
  UpdateScanWorkflowRequest,
  CreateStepRequest,
  UpdateStepRequest,
  QuickScanRequest,
  QuickScanResponse,
  ScanManagementOverview,
} from './scan-workflow-types'

// ============================================
// SWR CONFIGURATION
// ============================================

const defaultConfig: SWRConfiguration = {
  revalidateOnFocus: false,
  revalidateOnReconnect: true,
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
// CACHE KEYS
// ============================================

export const scanWorkflowKeys = {
  all: ['scan-workflows'] as const,
  lists: () => [...scanWorkflowKeys.all, 'list'] as const,
  list: (filters?: ScanWorkflowListFilters) => [...scanWorkflowKeys.lists(), filters] as const,
  details: () => [...scanWorkflowKeys.all, 'detail'] as const,
  detail: (id: string) => [...scanWorkflowKeys.details(), id] as const,
}

export const scanRunKeys = {
  all: ['scan-runs'] as const,
  lists: () => [...scanRunKeys.all, 'list'] as const,
  list: (filters?: ScanRunListFilters) => [...scanRunKeys.lists(), filters] as const,
  details: () => [...scanRunKeys.all, 'detail'] as const,
  detail: (id: string) => [...scanRunKeys.details(), id] as const,
}

export const scanManagementKeys = {
  stats: ['scans', 'overview-stats'] as const,
}

// ============================================
// FETCHER FUNCTIONS
// ============================================

async function fetchWorkflows(url: string): Promise<ScanWorkflowListResponse> {
  return get<ScanWorkflowListResponse>(url)
}

async function fetchWorkflow(url: string): Promise<ScanWorkflow> {
  return get<ScanWorkflow>(url)
}

async function fetchWorkflowRuns(url: string): Promise<ScanRunListResponse> {
  return get<ScanRunListResponse>(url)
}

async function fetchWorkflowRun(url: string): Promise<ScanRun> {
  return get<ScanRun>(url)
}

async function fetchScanManagementStats(url: string): Promise<ScanManagementOverview> {
  return get<ScanManagementOverview>(url)
}

// ============================================
// SCAN_WORKFLOW TEMPLATE HOOKS
// ============================================

/**
 * Fetch workflows list
 */
export function useScanWorkflows(filters?: ScanWorkflowListFilters, config?: SWRConfiguration) {
  const { currentTenant } = useTenant()

  const key = currentTenant ? scanWorkflowEndpoints.list(filters) : null

  return useSWR<ScanWorkflowListResponse>(key, fetchWorkflows, {
    ...defaultConfig,
    ...config,
  })
}

/**
 * Fetch a single workflow by ID
 */
export function useScanWorkflow(workflowId: string | null, config?: SWRConfiguration) {
  const { currentTenant } = useTenant()

  const key = currentTenant && workflowId ? scanWorkflowEndpoints.get(workflowId) : null

  return useSWR<ScanWorkflow>(key, fetchWorkflow, {
    ...defaultConfig,
    ...config,
  })
}

/**
 * Create a new workflow
 */
export function useCreateScanWorkflow() {
  const { currentTenant } = useTenant()

  return useSWRMutation(
    currentTenant ? scanWorkflowEndpoints.create() : null,
    async (url: string, { arg }: { arg: CreateScanWorkflowRequest }) => {
      return post<ScanWorkflow>(url, arg)
    }
  )
}

/**
 * Update a workflow
 */
export function useUpdateScanWorkflow(workflowId: string) {
  const { currentTenant } = useTenant()

  return useSWRMutation(
    currentTenant && workflowId ? scanWorkflowEndpoints.update(workflowId) : null,
    async (url: string, { arg }: { arg: UpdateScanWorkflowRequest }) => {
      return put<ScanWorkflow>(url, arg)
    }
  )
}

/**
 * Delete a workflow
 */
export function useDeleteScanWorkflow(workflowId: string) {
  const { currentTenant } = useTenant()

  return useSWRMutation(
    currentTenant && workflowId ? scanWorkflowEndpoints.delete(workflowId) : null,
    async (url: string) => {
      return del<void>(url)
    }
  )
}

/**
 * Activate a workflow
 */
export function useActivateScanWorkflow(workflowId: string) {
  const { currentTenant } = useTenant()

  return useSWRMutation(
    currentTenant && workflowId ? scanWorkflowEndpoints.activate(workflowId) : null,
    async (url: string) => {
      return post<ScanWorkflow>(url, {})
    }
  )
}

/**
 * Deactivate a workflow
 */
export function useDeactivateScanWorkflow(workflowId: string) {
  const { currentTenant } = useTenant()

  return useSWRMutation(
    currentTenant && workflowId ? scanWorkflowEndpoints.deactivate(workflowId) : null,
    async (url: string) => {
      return post<ScanWorkflow>(url, {})
    }
  )
}

/**
 * Clone a workflow
 */
export function useCloneScanWorkflow(workflowId: string) {
  const { currentTenant } = useTenant()

  return useSWRMutation(
    currentTenant && workflowId ? scanWorkflowEndpoints.clone(workflowId) : null,
    async (url: string, { arg }: { arg: { name: string } }) => {
      return post<ScanWorkflow>(url, arg)
    }
  )
}

// ============================================
// SCAN_WORKFLOW STEP HOOKS
// ============================================

/**
 * Add step to workflow
 */
export function useAddStep(workflowId: string) {
  const { currentTenant } = useTenant()

  return useSWRMutation(
    currentTenant && workflowId ? scanWorkflowEndpoints.addStep(workflowId) : null,
    async (url: string, { arg }: { arg: CreateStepRequest }) => {
      return post<ScanWorkflowStep>(url, arg)
    }
  )
}

/**
 * Update a step
 */
export function useUpdateStep(workflowId: string, stepId: string) {
  const { currentTenant } = useTenant()

  return useSWRMutation(
    currentTenant && workflowId && stepId
      ? scanWorkflowEndpoints.updateStep(workflowId, stepId)
      : null,
    async (url: string, { arg }: { arg: UpdateStepRequest }) => {
      return put<ScanWorkflowStep>(url, arg)
    }
  )
}

/**
 * Delete a step
 */
export function useDeleteStep(workflowId: string, stepId: string) {
  const { currentTenant } = useTenant()

  return useSWRMutation(
    currentTenant && workflowId && stepId
      ? scanWorkflowEndpoints.deleteStep(workflowId, stepId)
      : null,
    async (url: string) => {
      return del<void>(url)
    }
  )
}

// ============================================
// SCAN_WORKFLOW RUN HOOKS
// ============================================

/**
 * Fetch workflow runs list
 */
export function useScanRuns(filters?: ScanRunListFilters, config?: SWRConfiguration) {
  const { currentTenant } = useTenant()

  const key = currentTenant ? scanRunEndpoints.list(filters) : null

  return useSWR<ScanRunListResponse>(key, fetchWorkflowRuns, {
    ...defaultConfig,
    ...config,
  })
}

/**
 * Fetch a single workflow run by ID
 */
export function useScanRun(runId: string | null, config?: SWRConfiguration) {
  const { currentTenant } = useTenant()

  const key = currentTenant && runId ? scanRunEndpoints.get(runId) : null

  return useSWR<ScanRun>(key, fetchWorkflowRun, {
    ...defaultConfig,
    ...config,
  })
}

/**
 * Cancel a running workflow
 */
export function useCancelScanRun(runId: string) {
  const { currentTenant } = useTenant()

  return useSWRMutation(
    currentTenant && runId ? scanRunEndpoints.cancel(runId) : null,
    async (url: string) => {
      return post<ScanRun>(url, {})
    }
  )
}

// ============================================
// SCAN MANAGEMENT HOOKS
// ============================================

/**
 * Fetch scan management overview stats
 */
export function useScanManagementStats(config?: SWRConfiguration) {
  const { currentTenant } = useTenant()

  const key = currentTenant ? scanManagementEndpoints.stats() : null

  return useSWR<ScanManagementOverview>(key, fetchScanManagementStats, {
    ...defaultConfig,
    refreshInterval: 30000, // Refresh every 30 seconds
    ...config,
  })
}

/**
 * Quick scan targets
 */
export function useQuickScan() {
  const { currentTenant } = useTenant()

  return useSWRMutation(
    currentTenant ? scanManagementEndpoints.quickScan() : null,
    async (url: string, { arg }: { arg: QuickScanRequest }) => {
      return post<QuickScanResponse>(url, arg)
    }
  )
}

// ============================================
// CACHE UTILITIES
// ============================================

/**
 * Invalidate workflows cache
 */
export async function invalidateScanWorkflowsCache() {
  const { mutate } = await import('swr')
  await mutate(
    (key) => typeof key === 'string' && key.includes('/api/v1/scan-workflows'),
    undefined,
    {
      revalidate: true,
    }
  )
}

/**
 * Invalidate workflow runs cache
 */
export async function invalidateScanRunsCache() {
  const { mutate } = await import('swr')
  await mutate((key) => typeof key === 'string' && key.includes('/api/v1/scan-runs'), undefined, {
    revalidate: true,
  })
}

/**
 * Invalidate scan management stats cache
 */
export async function invalidateScanManagementStatsCache() {
  const { mutate } = await import('swr')
  await mutate(
    (key) => typeof key === 'string' && key.includes('/api/v1/scans/overview-stats'),
    undefined,
    {
      revalidate: true,
    }
  )
}

/**
 * Invalidate all workflow-related caches
 */
export async function invalidateAllScanWorkflowCaches() {
  await Promise.all([
    invalidateScanWorkflowsCache(),
    invalidateScanRunsCache(),
    invalidateScanManagementStatsCache(),
  ])
}
