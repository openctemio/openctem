'use client'

import useSWR from 'swr'
import { adminFetch, adminFetcher } from '@console/lib/admin-api/client'
import type { PlatformRoleAssignment, PlatformRolesCatalog } from '../types'

/** The platform permission catalog and built-in roles (any administrator). */
export function usePlatformRoles() {
  return useSWR<PlatformRolesCatalog>('/platform-roles/', adminFetcher)
}

/** Who holds which platform role (administrator roster readers). */
export function usePlatformRoleAssignments(enabled: boolean) {
  return useSWR<{ data: PlatformRoleAssignment[] }>(
    enabled ? '/platform-roles/assignments' : null,
    adminFetcher
  )
}

/** Gives an administrator an additional platform role (step-up, reason). */
export function assignPlatformRole(adminId: string, role: string, reason: string) {
  return adminFetch<void>(`/users/${encodeURIComponent(adminId)}/platform-roles`, {
    method: 'POST',
    body: { role, reason },
  })
}

/** Takes an additional platform role from an administrator (step-up, reason). */
export function revokePlatformRole(adminId: string, role: string, reason: string) {
  return adminFetch<void>(
    `/users/${encodeURIComponent(adminId)}/platform-roles/${encodeURIComponent(role)}`,
    { method: 'DELETE', body: { reason } }
  )
}
