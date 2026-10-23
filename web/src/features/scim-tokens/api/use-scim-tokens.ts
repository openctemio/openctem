/**
 * SCIM token hooks — SWR over /api/v1/scim-tokens (List/Create/Revoke/Rotate).
 * Tenant is determined from the JWT token. Revoke uses DELETE (the backend
 * marks the token revoked rather than removing the row).
 */

'use client'

import useSWR from 'swr'
import useSWRMutation from 'swr/mutation'
import { get, post, del } from '@/lib/api/client'
import { useTenant } from '@/context/tenant-provider'
import type {
  CreateScimTokenRequest,
  CreateScimTokenResponse,
  RotateScimTokenResponse,
  ScimTokenListResponse,
} from '../types/scim-token.types'

const BASE_URL = '/api/v1/scim-tokens'

/** Lists the tenant's SCIM tokens. Pass `enabled: false` for a user the API would refuse (not owner/admin). */
export function useScimTokens({ enabled = true }: { enabled?: boolean } = {}) {
  const { currentTenant } = useTenant()
  return useSWR<ScimTokenListResponse>(currentTenant && enabled ? BASE_URL : null, (url: string) =>
    get<ScimTokenListResponse>(url)
  )
}

export function useCreateScimToken() {
  const { currentTenant } = useTenant()
  return useSWRMutation(
    currentTenant ? BASE_URL : null,
    async (url: string, { arg }: { arg: CreateScimTokenRequest }) =>
      post<CreateScimTokenResponse>(url, arg)
  )
}

export function useRevokeScimToken() {
  const { currentTenant } = useTenant()
  return useSWRMutation(
    currentTenant ? BASE_URL : null,
    async (_url: string, { arg }: { arg: string }) => del<void>(`${BASE_URL}/${arg}`)
  )
}

/**
 * Rotates a token: the replacement's plaintext is returned once and the old
 * token keeps working for 24 hours, so the identity provider can switch.
 */
export function useRotateScimToken() {
  const { currentTenant } = useTenant()
  return useSWRMutation(
    currentTenant ? BASE_URL : null,
    async (_url: string, { arg }: { arg: string }) =>
      post<RotateScimTokenResponse>(`${BASE_URL}/${arg}/rotate`, {})
  )
}
