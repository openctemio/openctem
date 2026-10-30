/**
 * An organization's identity providers (Entra ID / Okta / Google Workspace),
 * configured by the platform administrator through the console API (RFC-022):
 * /api/v1/admin/tenants/{tenantId}/sso/identity-providers.
 */

'use client'

import useSWR, { type SWRConfiguration } from 'swr'

import { adminFetch, AdminApiError } from '@console/lib/admin-api/client'
import type {
  IdentityProvider,
  CreateIdentityProviderRequest,
  UpdateIdentityProviderRequest,
} from '@/features/sso/types/sso.types'
import type { SSOChange } from '@/features/sso-approvals/api/use-sso-changes'

const defaultConfig: SWRConfiguration = {
  revalidateOnFocus: false,
  revalidateOnReconnect: true,
  shouldRetryOnError: (error: unknown) => {
    const status = error instanceof AdminApiError ? error.status : undefined
    return !(status && status >= 400 && status < 500)
  },
  errorRetryCount: 3,
  errorRetryInterval: 1000,
  dedupingInterval: 2000,
}

const orgBase = (tenantId: string) => `/tenants/${tenantId}/sso/identity-providers`

/**
 * An organization's identity providers, plus the public address of the tenant
 * app (appUrl) that the redirect URI to register at the provider is built from.
 */
export function useOrgIdentityProviders(tenantId: string | null, config?: SWRConfiguration) {
  const swr = useSWR<{ providers: IdentityProvider[]; appUrl: string }>(
    tenantId ? orgBase(tenantId) : null,
    async (p: string) => {
      const res = await adminFetch<{ providers?: IdentityProvider[]; app_url?: string }>(p)
      return { providers: res.providers ?? [], appUrl: res.app_url ?? '' }
    },
    { ...defaultConfig, ...config }
  )
  return { ...swr, data: swr.data?.providers, appUrl: swr.data?.appUrl }
}

/**
 * Create/update answer 201/200 with the provider when the organization has no
 * owner yet, otherwise 202 with an SSO change waiting for an owner's approval.
 */
export function createOrgIdentityProvider(tenantId: string, input: CreateIdentityProviderRequest) {
  return adminFetch<IdentityProvider | SSOChange>(orgBase(tenantId), {
    method: 'POST',
    body: input,
  })
}

export function updateOrgIdentityProvider(
  tenantId: string,
  id: string,
  input: UpdateIdentityProviderRequest
) {
  return adminFetch<IdentityProvider | SSOChange>(`${orgBase(tenantId)}/${id}`, {
    method: 'PUT',
    body: input,
  })
}

export function deleteOrgIdentityProvider(tenantId: string, id: string) {
  return adminFetch<void>(`${orgBase(tenantId)}/${id}`, { method: 'DELETE' })
}
