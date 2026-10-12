/**
 * API Key hooks — SWR over /api/v1/api-keys (List/Create/Revoke/Delete).
 * Tenant is determined from the JWT token.
 */

'use client'

import useSWR, { mutate as globalMutate } from 'swr'
import useSWRMutation from 'swr/mutation'
import { get, post, del } from '@/lib/api/client'
import { useTenant } from '@/context/tenant-provider'
import type { APIKey, CreateAPIKeyRequest, CreateAPIKeyResponse } from '../types/api-key.types'

const BASE_URL = '/api/v1/api-keys'

interface APIKeyListResponse {
  data: APIKey[]
  total: number
  page: number
  per_page: number
  total_pages: number
}

export interface APIKeyListParams {
  /** 1-based, as the API pages. */
  page?: number
  perPage?: number
  search?: string
}

/** The list key: every page of the list starts with BASE_URL. */
export function apiKeysListKey(params: APIKeyListParams = {}): string {
  const q = new URLSearchParams()
  q.set('page', String(Math.max(1, params.page ?? 1)))
  q.set('per_page', String(params.perPage ?? 20))
  if (params.search) q.set('search', params.search)
  return `${BASE_URL}?${q.toString()}`
}

/** Revalidate every cached page of the list after a create/revoke/delete. */
function revalidateApiKeyLists() {
  return globalMutate((key) => typeof key === 'string' && key.startsWith(`${BASE_URL}?`))
}

/**
 * One server page of API keys. The list used to fetch a single capped page
 * (`per_page=100`) and page it in the browser, hiding every key past it
 * (23a B20).
 */
export function useApiKeys(params: APIKeyListParams = {}) {
  const { currentTenant } = useTenant()
  return useSWR<APIKeyListResponse>(currentTenant ? apiKeysListKey(params) : null, (url: string) =>
    get<APIKeyListResponse>(url)
  )
}

export function useCreateApiKey() {
  const { currentTenant } = useTenant()
  return useSWRMutation(
    currentTenant ? BASE_URL : null,
    async (url: string, { arg }: { arg: CreateAPIKeyRequest }) => {
      const res = await post<CreateAPIKeyResponse>(url, arg)
      void revalidateApiKeyLists()
      return res
    }
  )
}

export function useRevokeApiKey() {
  const { currentTenant } = useTenant()
  return useSWRMutation(
    currentTenant ? BASE_URL : null,
    async (_url: string, { arg }: { arg: string }) => {
      await post<void>(`${BASE_URL}/${arg}/revoke`, {})
      void revalidateApiKeyLists()
    }
  )
}

export function useDeleteApiKey() {
  const { currentTenant } = useTenant()
  return useSWRMutation(
    currentTenant ? BASE_URL : null,
    async (_url: string, { arg }: { arg: string }) => {
      await del<void>(`${BASE_URL}/${arg}`)
      void revalidateApiKeyLists()
    }
  )
}
