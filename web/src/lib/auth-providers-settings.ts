import { env } from '@/lib/env'
import type { AuthProvidersResponse } from '@/features/auth/api/use-auth-providers'

/**
 * The public sign-in options (GET /api/v1/auth/providers: social providers,
 * open registration, password policy...) read on the server for the sign-in
 * and sign-up pages, with the same short cache as the legal settings
 * (src/lib/legal-settings.ts). The pages hand it to the browser's providers
 * hook as its first value, so the cards render their final state on first
 * paint instead of growing when the answer arrives; the browser still asks
 * once, as before. Undefined when the API cannot be reached: the page then
 * waits for the browser's answer as before.
 */
export async function authProvidersSettings(): Promise<AuthProvidersResponse | undefined> {
  try {
    const res = await fetch(`${env.api.url}/api/v1/auth/providers`, {
      headers: { Accept: 'application/json' },
      next: { revalidate: 60 },
      signal: AbortSignal.timeout(3000),
    })
    if (!res.ok) return undefined
    return (await res.json()) as AuthProvidersResponse
  } catch {
    return undefined
  }
}
