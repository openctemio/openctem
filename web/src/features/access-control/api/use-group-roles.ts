'use client'

/**
 * Team role bindings (GET/POST/DELETE /api/v1/groups/{groupId}/roles) and the
 * end date of a team membership (PATCH /api/v1/groups/{groupId}/members/{userId}).
 */

import useSWR, { mutate as globalMutate } from 'swr'
import { fetcher, fetcherWithOptions } from '@/lib/api/client'
import type { GroupRoleBinding, SetGroupMemberExpiryInput } from '../types'

const API_BASE = '/api/v1/groups'

export function groupRolesKey(groupId: string): string {
  return `${API_BASE}/${encodeURIComponent(groupId)}/roles`
}

/** The roles bound to a team (null id or skip: nothing is fetched). */
export function useGroupRoles(groupId: string | null, options?: { skip?: boolean }) {
  const { data, error, isLoading, mutate } = useSWR<{ data: GroupRoleBinding[] }>(
    groupId && !options?.skip ? groupRolesKey(groupId) : null,
    fetcher
  )
  return { roles: data?.data ?? [], error, isLoading, mutate }
}

export async function bindGroupRole(groupId: string, roleId: string): Promise<void> {
  await fetcherWithOptions<void>(groupRolesKey(groupId), {
    method: 'POST',
    body: JSON.stringify({ role_id: roleId }),
  })
  await globalMutate(groupRolesKey(groupId))
}

export async function unbindGroupRole(groupId: string, roleId: string): Promise<void> {
  await fetcherWithOptions<void>(`${groupRolesKey(groupId)}/${encodeURIComponent(roleId)}`, {
    method: 'DELETE',
  })
  await globalMutate(groupRolesKey(groupId))
}

export async function setGroupMemberExpiry(
  groupId: string,
  userId: string,
  input: SetGroupMemberExpiryInput
): Promise<void> {
  await fetcherWithOptions<void>(
    `${API_BASE}/${encodeURIComponent(groupId)}/members/${encodeURIComponent(userId)}`,
    { method: 'PATCH', body: JSON.stringify(input) }
  )
}
