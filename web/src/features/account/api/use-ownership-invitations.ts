/**
 * Ownership invitations addressed to the signed-in account
 * (API docs: architecture/organization-ownership-invitations.md). A platform
 * administrator created an organization for this account; it becomes the
 * owner only by accepting here (with a recent sign-in: the API answers
 * STEP_UP_REQUIRED and the shared client asks for it, then retries).
 */

import useSWR from 'swr'
import { get, post } from '@/lib/api/client'
import { useBootstrapPending } from '@/context/bootstrap-provider'

export interface OwnershipInvitation {
  id: string
  organization_id: string
  organization_name: string
  organization_slug: string
  invited_at: string
  expires_at: string
}

export interface OwnershipInvitationList {
  data: OwnershipInvitation[]
}

export const OWNERSHIP_INVITATIONS_ENDPOINT = '/api/v1/me/ownership-invitations'

/**
 * `enabled: false` skips the read (no session that can make it yet). In the
 * app shell the session bootstrap carries the list (bootstrap-session.ts), so
 * the hook waits for it and does not send a request of its own.
 */
export function useOwnershipInvitations(enabled = true) {
  const bootstrapPending = useBootstrapPending()
  const { data, error, isLoading, mutate } = useSWR<OwnershipInvitationList>(
    enabled && !bootstrapPending ? OWNERSHIP_INVITATIONS_ENDPOINT : null,
    (url: string) => get<OwnershipInvitationList>(url),
    { revalidateOnFocus: false, revalidateIfStale: false }
  )
  return { invitations: data?.data ?? [], error, isLoading, mutate }
}

export function acceptOwnershipInvitation(id: string) {
  return post<{ organization_id: string }>(
    `${OWNERSHIP_INVITATIONS_ENDPOINT}/${encodeURIComponent(id)}/accept`
  )
}

export function declineOwnershipInvitation(id: string) {
  return post<void>(`${OWNERSHIP_INVITATIONS_ENDPOINT}/${encodeURIComponent(id)}/decline`)
}
