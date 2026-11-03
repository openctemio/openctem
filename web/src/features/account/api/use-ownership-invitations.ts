/**
 * Ownership invitations addressed to the signed-in account
 * (API docs: architecture/organization-ownership-invitations.md). A platform
 * administrator created an organization for this account; it becomes the
 * owner only by accepting here (with a recent sign-in: the API answers
 * STEP_UP_REQUIRED and the shared client asks for it, then retries).
 */

import useSWR from 'swr'
import { get, post } from '@/lib/api/client'

export interface OwnershipInvitation {
  id: string
  organization_id: string
  organization_name: string
  organization_slug: string
  invited_at: string
  expires_at: string
}

interface OwnershipInvitationList {
  data: OwnershipInvitation[]
}

export const OWNERSHIP_INVITATIONS_ENDPOINT = '/api/v1/me/ownership-invitations'

export function useOwnershipInvitations() {
  const { data, error, isLoading, mutate } = useSWR<OwnershipInvitationList>(
    OWNERSHIP_INVITATIONS_ENDPOINT,
    (url: string) => get<OwnershipInvitationList>(url),
    { revalidateOnFocus: false }
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
