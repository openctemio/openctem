'use client'

import useSWR from 'swr'
import { get } from '@/lib/api/client'
import { useTenant } from '@/context/tenant-provider'
import { fetchFindings, type ApprovalListResponse } from '@/features/findings/api/use-findings-api'
import type { ApiFindingListResponse } from '@/features/findings/api/finding-api.types'
import { approvalQueueEndpoint, findingsQueueEndpoint, type ApprovalQueueTab } from '../lib/queues'

const QUEUE_SWR = {
  revalidateOnFocus: true,
  keepPreviousData: true,
  errorRetryCount: 1,
  dedupingInterval: 5_000,
}

/** One page of a finding queue: the view's params, ordered for the queue. */
export function useFindingQueue(params: string | undefined, sort: string, enabled: boolean) {
  const { currentTenant } = useTenant()
  const key =
    enabled && currentTenant?.id && params !== undefined
      ? findingsQueueEndpoint(params, sort)
      : null
  return useSWR<ApiFindingListResponse>(key, fetchFindings, QUEUE_SWR)
}

/**
 * One page of an approval queue, with both queues' pending counts. With
 * `perPage` 1 it serves only the counts (the tab is not open).
 */
export function useApprovalQueue(queue: ApprovalQueueTab, perPage: number, enabled = true) {
  const { currentTenant } = useTenant()
  const key = enabled && currentTenant?.id ? approvalQueueEndpoint(queue, perPage) : null
  return useSWR<ApprovalListResponse>(
    key,
    (url: string) => get<ApprovalListResponse>(url),
    QUEUE_SWR
  )
}
