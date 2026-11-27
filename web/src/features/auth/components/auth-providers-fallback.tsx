'use client'

import type { ReactNode } from 'react'
import { SWRConfig } from 'swr'

import type { AuthProvidersResponse } from '../api/use-auth-providers'

/** The key `useAuthProviders` reads (its request path). */
export const AUTH_PROVIDERS_KEY = '/api/v1/auth/providers'

/**
 * Gives every `useAuthProviders` below it the answer the page read on the
 * server as its first value (src/lib/auth-providers-settings.ts), so nothing
 * on the card appears or grows when the browser's own answer arrives.
 */
export function AuthProvidersFallback({
  providers,
  children,
}: {
  providers: AuthProvidersResponse | undefined
  children: ReactNode
}) {
  if (!providers) return <>{children}</>
  return <SWRConfig value={{ fallback: { [AUTH_PROVIDERS_KEY]: providers } }}>{children}</SWRConfig>
}
