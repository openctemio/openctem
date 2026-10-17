/**
 * SSO hooks of the tenant app: the login page reads an organization's active
 * providers from the public /api/v1/auth/sso/providers endpoint. Identity
 * providers are configured in the platform console (web/console).
 */

'use client'

import useSWR, { type SWRConfiguration } from 'swr'

import { get } from '@/lib/api/client'
import type { SSOProviderInfo } from '../types/sso.types'

const defaultConfig: SWRConfiguration = {
  revalidateOnFocus: false,
  revalidateOnReconnect: true,
  shouldRetryOnError: (error: unknown) => {
    const status = (error as { statusCode?: number })?.statusCode
    return !(status && status >= 400 && status < 500)
  },
  errorRetryCount: 3,
  errorRetryInterval: 1000,
  dedupingInterval: 2000,
}

// ============================================
// PUBLIC HOOKS (Login page)
// ============================================

/**
 * List active SSO providers for a tenant (public, no auth required)
 */
export function useTenantSSOProviders(orgSlug: string | null, config?: SWRConfiguration) {
  const key = orgSlug ? `/api/v1/auth/sso/providers?org=${encodeURIComponent(orgSlug)}` : null

  return useSWR<SSOProviderInfo[]>(
    key,
    async (url: string) => {
      const res = await get<{ providers: SSOProviderInfo[] }>(url)
      return res.providers ?? []
    },
    {
      ...defaultConfig,
      revalidateOnFocus: false,
      ...config,
    }
  )
}
