'use client'

import useSWR from 'swr'
import { adminFetch, adminFetcher } from '@console/lib/admin-api/client'
import type { AdminApproval, AdminApprovalList } from '../types'

/** Four-eyes approval requests and whether approvals are on (super admin). */
export function useAdminApprovals(enabled: boolean) {
  // Not polled: the page reloads on focus and after every decision.
  return useSWR<AdminApprovalList>(enabled ? '/approvals' : null, adminFetcher)
}

/** Asks another super admin to approve an action on its exact target (step-up). */
export function requestAdminApproval(input: { action: string; target: string; reason: string }) {
  return adminFetch<AdminApproval>('/approvals', { method: 'POST', body: input })
}

/** Approves another super admin's request (fresh step-up). */
export function approveAdminApproval(id: string, note: string) {
  return adminFetch<AdminApproval>(`/approvals/${encodeURIComponent(id)}/approve`, {
    method: 'POST',
    body: { note },
  })
}

/** Rejects another super admin's request (step-up). */
export function rejectAdminApproval(id: string, note: string) {
  return adminFetch<AdminApproval>(`/approvals/${encodeURIComponent(id)}/reject`, {
    method: 'POST',
    body: { note },
  })
}

/** Withdraws the caller's own request. */
export function cancelAdminApproval(id: string) {
  return adminFetch<AdminApproval>(`/approvals/${encodeURIComponent(id)}/cancel`, {
    method: 'POST',
  })
}
