/**
 * The members who may be assigned one finding (GET
 * /api/v1/findings/{id}/assignable): active members who can read it, so a
 * finding is never assigned to someone who could not see it. The server is
 * the only judge; the picker lists what it returns. No emails.
 */

import useSWR from 'swr'
import { get } from '@/lib/api/client'
import { useTenant } from '@/context/tenant-provider'

export interface AssignableMember {
  user_id: string
  name: string
  avatar_url?: string
  role: string
  /** Never sent by this endpoint; present so pickers share one member shape. */
  email?: string
}

export function assignableMembersKey(findingId: string, search: string, limit: number): string {
  const params = new URLSearchParams({ limit: String(limit) })
  if (search) params.set('q', search)
  return `/api/v1/findings/${encodeURIComponent(findingId)}/assignable?${params.toString()}`
}

/** A null finding id (or `enabled` false) disables the request. */
export function useAssignableMembers(
  findingId: string | null | undefined,
  options: { search?: string; limit?: number; enabled?: boolean } = {}
) {
  const { currentTenant } = useTenant()
  const { search = '', limit = 20, enabled = true } = options
  const key =
    currentTenant && findingId && enabled ? assignableMembersKey(findingId, search, limit) : null
  const { data, isLoading } = useSWR<{ data: AssignableMember[] }>(
    key,
    (url: string) => get<{ data: AssignableMember[] }>(url),
    { revalidateOnFocus: false }
  )
  return { members: data?.data ?? [], isLoading }
}
