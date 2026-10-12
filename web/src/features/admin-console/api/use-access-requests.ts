'use client'

import useSWR from 'swr'
import type {
  AccessRequest,
  AccessRequestList,
  ApproveAccessRequestInput,
  ApproveAccessRequestResult,
} from '@/lib/api/generated'
import { adminFetch, adminFetcher } from './admin-client'

export type AccessRequestStatusFilter = '' | 'pending' | 'unconfirmed' | 'approved' | 'rejected'

/** The request-access queue (any administrator). Empty status: open requests. */
export function useAccessRequests(status: AccessRequestStatusFilter) {
  const qs = status ? `?status=${encodeURIComponent(status)}` : ''
  return useSWR<AccessRequestList>(`/access-requests${qs}`, adminFetcher)
}

/** Creates the organization with the requester as owner (ops_admin+). */
export function approveAccessRequest(id: string, input: ApproveAccessRequestInput) {
  return adminFetch<ApproveAccessRequestResult>(
    `/access-requests/${encodeURIComponent(id)}/approve`,
    { method: 'POST', body: input }
  )
}

/** Declines a request (ops_admin+). */
export function rejectAccessRequest(id: string) {
  return adminFetch<AccessRequest>(`/access-requests/${encodeURIComponent(id)}/reject`, {
    method: 'POST',
  })
}
