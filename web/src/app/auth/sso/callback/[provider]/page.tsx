/**
 * SSO Callback Page
 *
 * Handles SSO callback from identity providers (Entra ID, Okta, Google Workspace)
 * Processes the authorization code and redirects to the dashboard
 */

import { redirect } from 'next/navigation'
import { loginErrorHref } from '@/features/auth/lib/login-error'
import { cookies } from 'next/headers'

import { handleSSOCallback } from '@/features/sso/actions/sso-auth-actions'
import { validateRedirectUrl } from '@/lib/redirect'
import type { SSOProviderType } from '@/features/sso/types/sso.types'

// ============================================
// TYPES
// ============================================

interface SSOCallbackPageProps {
  params: Promise<{
    provider: string
  }>
  searchParams: Promise<{
    code?: string
    state?: string
    error?: string
    error_description?: string
  }>
}

// ============================================
// VALID PROVIDERS
// ============================================

const validProviders: SSOProviderType[] = ['entra_id', 'okta', 'google_workspace']

function isValidProvider(provider: string): provider is SSOProviderType {
  return validProviders.includes(provider as SSOProviderType)
}

// ============================================
// PAGE
// ============================================

export default async function SSOCallbackPage({ params, searchParams }: SSOCallbackPageProps) {
  const { provider } = await params
  const { code, state, error } = await searchParams

  // Get stored cookies before any processing (they may be deleted during callback)
  const cookieStore = await cookies()
  const orgSlug = cookieStore.get('sso_org')?.value || ''
  const org = orgSlug ? { org: orgSlug } : undefined
  const storedRedirectTo = validateRedirectUrl(cookieStore.get('sso_redirect')?.value, '/')

  // Validate provider
  if (!isValidProvider(provider)) {
    redirect(loginErrorHref('invalid_provider', org))
  }

  // Handle OAuth error from provider
  if (error) {
    // error_description is the provider's free text: never echo it on /login.
    redirect(loginErrorHref('provider_error', org))
  }

  // Validate required parameters
  if (!code || !state) {
    redirect(loginErrorHref('missing_params', org))
  }

  // Process the SSO callback
  const result = await handleSSOCallback(provider, code, state)

  if (!result.success) {
    redirect(loginErrorHref('callback_failed', org))
  }

  // Redirect to stored destination (read before callback deleted the cookie)
  redirect(storedRedirectTo)
}

// ============================================
// STATIC PARAMS
// ============================================

export function generateStaticParams() {
  return validProviders.map((provider) => ({
    provider,
  }))
}
