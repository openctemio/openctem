'use client'

/**
 * The readiness of the workflow a scan form has chosen, from the same
 * request the What step makes (GET /scan-workflows?include=readiness, the
 * caller's organization; SWR shares it). Undefined while unknown, for a
 * single-scanner scan, or when workflows are off.
 */

import { useScanWorkflows } from '@/lib/api/scan-workflow-hooks'
import type { WorkflowReadiness } from '@/features/scan-workflows/lib/readiness'
import type { NewScanFormData } from '../types'

/** The list parameters the What step uses (one cached request). */
export const READINESS_LIST_PARAMS = {
  is_active: true,
  per_page: 100,
  include: 'readiness',
} as const

export function useWorkflowReadiness(
  form: Pick<NewScanFormData, 'mode' | 'workflowId'>,
  enabled: boolean
): WorkflowReadiness | undefined {
  const wanted = enabled && form.mode === 'workflow' && !!form.workflowId
  const { data } = useScanWorkflows(wanted ? { ...READINESS_LIST_PARAMS } : null, {
    revalidateOnFocus: false,
  })
  if (!wanted) return undefined
  return data?.data?.find((w) => w.id === form.workflowId)?.readiness ?? undefined
}
