/**
 * Service accounts: organization-owned identities for integrations
 * (/api/v1/service-accounts). They never sign in; they act through API keys
 * minted for them, which carry at most what the account holds.
 */

'use client'

import useSWR, { mutate as globalMutate } from 'swr'
import useSWRMutation from 'swr/mutation'
import { get, post, del } from '@/lib/api/client'
import { useTenant } from '@/context/tenant-provider'
import type {
  APIKey,
  CreateAPIKeyRequest,
  CreateAPIKeyResponse,
} from '@/features/api-keys/types/api-key.types'

export const SERVICE_ACCOUNTS_URL = '/api/v1/service-accounts'

export interface ServiceAccount {
  id: string
  name: string
  description?: string
  owner_id?: string
  owner_name?: string
  status: string
  /** Number of API keys the account holds. */
  api_keys: number
  created_at: string
}

export interface CreateServiceAccountRequest {
  name: string
  description?: string
}

export function serviceAccountKeysUrl(accountId: string): string {
  return `${SERVICE_ACCOUNTS_URL}/${encodeURIComponent(accountId)}/api-keys`
}

function revalidateAccounts() {
  return globalMutate(SERVICE_ACCOUNTS_URL)
}

export function useServiceAccounts() {
  const { currentTenant } = useTenant()
  return useSWR<{ data: ServiceAccount[] }>(
    currentTenant ? SERVICE_ACCOUNTS_URL : null,
    (url: string) => get<{ data: ServiceAccount[] }>(url)
  )
}

export function useCreateServiceAccount() {
  return useSWRMutation(
    SERVICE_ACCOUNTS_URL,
    async (url: string, { arg }: { arg: CreateServiceAccountRequest }) => {
      const res = await post<ServiceAccount>(url, arg)
      void revalidateAccounts()
      return res
    }
  )
}

export function useDeleteServiceAccount() {
  return useSWRMutation(SERVICE_ACCOUNTS_URL, async (_url: string, { arg }: { arg: string }) => {
    await del<void>(`${SERVICE_ACCOUNTS_URL}/${encodeURIComponent(arg)}`)
    void revalidateAccounts()
  })
}

/** The keys of one service account (null id: nothing is fetched). */
export function useServiceAccountKeys(accountId: string | null) {
  return useSWR<{ data: APIKey[]; total: number }>(
    accountId ? `${serviceAccountKeysUrl(accountId)}?per_page=100` : null,
    (url: string) => get<{ data: APIKey[]; total: number }>(url)
  )
}

function revalidateKeys(accountId: string) {
  void revalidateAccounts()
  return globalMutate(
    (key) => typeof key === 'string' && key.startsWith(`${serviceAccountKeysUrl(accountId)}?`)
  )
}

export function useCreateServiceAccountKey(accountId: string) {
  return useSWRMutation(
    serviceAccountKeysUrl(accountId),
    async (url: string, { arg }: { arg: CreateAPIKeyRequest }) => {
      const res = await post<CreateAPIKeyResponse>(url, arg)
      void revalidateKeys(accountId)
      return res
    }
  )
}

export function useDeleteServiceAccountKey(accountId: string) {
  return useSWRMutation(
    serviceAccountKeysUrl(accountId),
    async (url: string, { arg }: { arg: string }) => {
      await del<void>(`${url}/${encodeURIComponent(arg)}`)
      void revalidateKeys(accountId)
    }
  )
}
