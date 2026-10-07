/**
 * Pipeline API Hooks
 *
 * SWR hooks for Pipeline Management (Workflow Orchestration)
 */

'use client'

import useSWR, { type SWRConfiguration } from 'swr'
import useSWRMutation from 'swr/mutation'
import { get, post, put, del } from './client'
import { handleApiError } from './error-handler'
import { useTenant } from '@/context/tenant-provider'
import { scanWorkflowEndpoints, scanRunEndpoints, scanManagementEndpoints } from './endpoints'
import type {
  PipelineTemplate,
  PipelineListResponse,
  PipelineListFilters,
  PipelineRun,
  PipelineRunListResponse,
  PipelineRunListFilters,
  PipelineStep,
  CreatePipelineRequest,
  UpdatePipelineRequest,
  CreateStepRequest,
  UpdateStepRequest,
  QuickScanRequest,
  QuickScanResponse,
  ScanManagementOverview,
} from './pipeline-types'

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

export const pipelineKeys = {
  all: ['pipelines'] as const,
  lists: () => [...pipelineKeys.all, 'list'] as const,
  list: (filters?: PipelineListFilters) => [...pipelineKeys.lists(), filters] as const,
  details: () => [...pipelineKeys.all, 'detail'] as const,
  detail: (id: string) => [...pipelineKeys.details(), id] as const,
}

export const pipelineRunKeys = {
  all: ['scan-runs'] as const,
  lists: () => [...pipelineRunKeys.all, 'list'] as const,
  list: (filters?: PipelineRunListFilters) => [...pipelineRunKeys.lists(), filters] as const,
  details: () => [...pipelineRunKeys.all, 'detail'] as const,
  detail: (id: string) => [...pipelineRunKeys.details(), id] as const,
}

export const scanManagementKeys = {
  stats: ['scans', 'overview-stats'] as const,
}

// ============================================
// FETCHER FUNCTIONS
// ============================================

async function fetchPipelines(url: string): Promise<PipelineListResponse> {
  return get<PipelineListResponse>(url)
}

async function fetchPipeline(url: string): Promise<PipelineTemplate> {
  return get<PipelineTemplate>(url)
}

async function fetchPipelineRuns(url: string): Promise<PipelineRunListResponse> {
  return get<PipelineRunListResponse>(url)
}

async function fetchPipelineRun(url: string): Promise<PipelineRun> {
  return get<PipelineRun>(url)
}

async function fetchScanManagementStats(url: string): Promise<ScanManagementOverview> {
  return get<ScanManagementOverview>(url)
}

// ============================================
// PIPELINE TEMPLATE HOOKS
// ============================================

/**
 * Fetch pipelines list
 */
export function usePipelines(filters?: PipelineListFilters, config?: SWRConfiguration) {
  const { currentTenant } = useTenant()

  const key = currentTenant ? scanWorkflowEndpoints.list(filters) : null

  return useSWR<PipelineListResponse>(key, fetchPipelines, {
    ...defaultConfig,
    ...config,
  })
}

/**
 * Fetch a single pipeline by ID
 */
export function usePipeline(pipelineId: string | null, config?: SWRConfiguration) {
  const { currentTenant } = useTenant()

  const key = currentTenant && pipelineId ? scanWorkflowEndpoints.get(pipelineId) : null

  return useSWR<PipelineTemplate>(key, fetchPipeline, {
    ...defaultConfig,
    ...config,
  })
}

/**
 * Create a new pipeline
 */
export function useCreatePipeline() {
  const { currentTenant } = useTenant()

  return useSWRMutation(
    currentTenant ? scanWorkflowEndpoints.create() : null,
    async (url: string, { arg }: { arg: CreatePipelineRequest }) => {
      return post<PipelineTemplate>(url, arg)
    }
  )
}

/**
 * Update a pipeline
 */
export function useUpdatePipeline(pipelineId: string) {
  const { currentTenant } = useTenant()

  return useSWRMutation(
    currentTenant && pipelineId ? scanWorkflowEndpoints.update(pipelineId) : null,
    async (url: string, { arg }: { arg: UpdatePipelineRequest }) => {
      return put<PipelineTemplate>(url, arg)
    }
  )
}

/**
 * Delete a pipeline
 */
export function useDeletePipeline(pipelineId: string) {
  const { currentTenant } = useTenant()

  return useSWRMutation(
    currentTenant && pipelineId ? scanWorkflowEndpoints.delete(pipelineId) : null,
    async (url: string) => {
      return del<void>(url)
    }
  )
}

/**
 * Activate a pipeline
 */
export function useActivatePipeline(pipelineId: string) {
  const { currentTenant } = useTenant()

  return useSWRMutation(
    currentTenant && pipelineId ? scanWorkflowEndpoints.activate(pipelineId) : null,
    async (url: string) => {
      return post<PipelineTemplate>(url, {})
    }
  )
}

/**
 * Deactivate a pipeline
 */
export function useDeactivatePipeline(pipelineId: string) {
  const { currentTenant } = useTenant()

  return useSWRMutation(
    currentTenant && pipelineId ? scanWorkflowEndpoints.deactivate(pipelineId) : null,
    async (url: string) => {
      return post<PipelineTemplate>(url, {})
    }
  )
}

/**
 * Clone a pipeline
 */
export function useClonePipeline(pipelineId: string) {
  const { currentTenant } = useTenant()

  return useSWRMutation(
    currentTenant && pipelineId ? scanWorkflowEndpoints.clone(pipelineId) : null,
    async (url: string, { arg }: { arg: { name: string } }) => {
      return post<PipelineTemplate>(url, arg)
    }
  )
}

// ============================================
// PIPELINE STEP HOOKS
// ============================================

/**
 * Add step to pipeline
 */
export function useAddStep(pipelineId: string) {
  const { currentTenant } = useTenant()

  return useSWRMutation(
    currentTenant && pipelineId ? scanWorkflowEndpoints.addStep(pipelineId) : null,
    async (url: string, { arg }: { arg: CreateStepRequest }) => {
      return post<PipelineStep>(url, arg)
    }
  )
}

/**
 * Update a step
 */
export function useUpdateStep(pipelineId: string, stepId: string) {
  const { currentTenant } = useTenant()

  return useSWRMutation(
    currentTenant && pipelineId && stepId
      ? scanWorkflowEndpoints.updateStep(pipelineId, stepId)
      : null,
    async (url: string, { arg }: { arg: UpdateStepRequest }) => {
      return put<PipelineStep>(url, arg)
    }
  )
}

/**
 * Delete a step
 */
export function useDeleteStep(pipelineId: string, stepId: string) {
  const { currentTenant } = useTenant()

  return useSWRMutation(
    currentTenant && pipelineId && stepId
      ? scanWorkflowEndpoints.deleteStep(pipelineId, stepId)
      : null,
    async (url: string) => {
      return del<void>(url)
    }
  )
}

// ============================================
// PIPELINE RUN HOOKS
// ============================================

/**
 * Fetch pipeline runs list
 */
export function usePipelineRuns(filters?: PipelineRunListFilters, config?: SWRConfiguration) {
  const { currentTenant } = useTenant()

  const key = currentTenant ? scanRunEndpoints.list(filters) : null

  return useSWR<PipelineRunListResponse>(key, fetchPipelineRuns, {
    ...defaultConfig,
    ...config,
  })
}

/**
 * Fetch a single pipeline run by ID
 */
export function usePipelineRun(runId: string | null, config?: SWRConfiguration) {
  const { currentTenant } = useTenant()

  const key = currentTenant && runId ? scanRunEndpoints.get(runId) : null

  return useSWR<PipelineRun>(key, fetchPipelineRun, {
    ...defaultConfig,
    ...config,
  })
}

/**
 * Cancel a running pipeline
 */
export function useCancelPipelineRun(runId: string) {
  const { currentTenant } = useTenant()

  return useSWRMutation(
    currentTenant && runId ? scanRunEndpoints.cancel(runId) : null,
    async (url: string) => {
      return post<PipelineRun>(url, {})
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
 * Invalidate pipelines cache
 */
export async function invalidatePipelinesCache() {
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
 * Invalidate pipeline runs cache
 */
export async function invalidatePipelineRunsCache() {
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
 * Invalidate all pipeline-related caches
 */
export async function invalidateAllPipelineCaches() {
  await Promise.all([
    invalidatePipelinesCache(),
    invalidatePipelineRunsCache(),
    invalidateScanManagementStatsCache(),
  ])
}
