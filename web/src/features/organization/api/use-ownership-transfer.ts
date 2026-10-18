/**
 * Ownership transfer (api RFC-095 §3.1): the owner asks a member to take the
 * organization; the member accepts with their own re-authentication within
 * 72 hours, or declines; the owner can cancel until then.
 */

import useSWR from 'swr'
import { tenantEndpoints } from '@/lib/api/endpoints'
import { fetcherWithOptions } from '@/lib/api/client'
import { ApiClientError } from '@/lib/api/error-handler'
import type { MemberRole } from '../types/member.types'

export type PreviousOwnerRole = Exclude<MemberRole, 'owner'>

export interface OwnershipTransfer {
  id: string
  status: 'pending' | 'accepted' | 'canceled' | 'declined' | 'expired'
  from_user_id: string
  from_name?: string
  to_user_id: string
  to_name?: string
  previous_owner_role: PreviousOwnerRole
  make_internal: boolean
  created_at: string
  expires_at: string
  /** The caller's side: the owner who asked, or the member asked. */
  viewer: 'owner' | 'new_owner'
}

export interface StartOwnershipTransferInput {
  member_id: string
  previous_owner_role: PreviousOwnerRole
  confirm_internal?: boolean
}

/** The open request, or null when there is none the caller may see (the API answers 200 null; an older API answered 404). */
async function fetchPending(url: string): Promise<OwnershipTransfer | null> {
  try {
    return await fetcherWithOptions<OwnershipTransfer>(url, { method: 'GET' })
  } catch (err) {
    if (err instanceof ApiClientError && err.statusCode === 404) return null
    throw err
  }
}

/** The pending transfer the caller is part of (owner or member asked). */
export function usePendingOwnershipTransfer(enabled = true) {
  const { data, error, isLoading, mutate } = useSWR<OwnershipTransfer | null>(
    enabled ? tenantEndpoints.ownershipTransfer() : null,
    fetchPending,
    { revalidateOnFocus: true, shouldRetryOnError: false }
  )
  return { transfer: data ?? null, error, isLoading, mutate }
}

export function startOwnershipTransfer(input: StartOwnershipTransferInput) {
  return fetcherWithOptions<OwnershipTransfer>(tenantEndpoints.ownershipTransfer(), {
    method: 'POST',
    body: JSON.stringify(input),
  })
}

export function cancelOwnershipTransfer() {
  return fetcherWithOptions<void>(tenantEndpoints.ownershipTransfer(), { method: 'DELETE' })
}

export function acceptOwnershipTransfer() {
  return fetcherWithOptions<OwnershipTransfer>(tenantEndpoints.approveOwnershipTransfer(), {
    method: 'POST',
  })
}

export function declineOwnershipTransfer() {
  return fetcherWithOptions<void>(tenantEndpoints.rejectOwnershipTransfer(), { method: 'POST' })
}
