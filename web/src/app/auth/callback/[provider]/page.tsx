/**
 * OAuth Callback Page
 *
 * Handles OAuth callback from social providers (Google, GitHub, Microsoft)
 * Processes the authorization code and redirects to the appropriate page
 */

import { redirect } from 'next/navigation'
import { NOT_SET_UP_PATH, SIGNUP_NOT_AVAILABLE } from '@/features/auth/lib/signup-outcome'
import { loginErrorHref } from '@/features/auth/lib/login-error'
import { cookies } from 'next/headers'

import {
  handleOAuthCallback,
  type SocialProvider,
} from '@/features/auth/actions/social-auth-actions'
import { validateRedirectUrl } from '@/lib/redirect'

// ============================================
// TYPES
// ============================================

interface OAuthCallbackPageProps {
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

const validProviders: SocialProvider[] = ['google', 'github', 'microsoft']

function isValidProvider(provider: string): provider is SocialProvider {
  return validProviders.includes(provider as SocialProvider)
}

// ============================================
// PAGE COMPONENT
// ============================================

export default async function OAuthCallbackPage({ params, searchParams }: OAuthCallbackPageProps) {
  const { provider } = await params
  const { code, state, error } = await searchParams

  // Validate provider
  if (!isValidProvider(provider)) {
    redirect(loginErrorHref('invalid_provider'))
  }

  // Handle OAuth error from provider
  if (error) {
    // error_description is the provider's free text: never echo it on /login.
    redirect(loginErrorHref('provider_error'))
  }

  // Validate required parameters
  if (!code || !state) {
    redirect(loginErrorHref('missing_params'))
  }

  // Process the OAuth callback
  const result = await handleOAuthCallback(provider, code, state)

  if (!result.success) {
    // The sign-up policy refused to create an account: the one "not set up"
    // page, whatever the reason.
    if (result.code === SIGNUP_NOT_AVAILABLE) redirect(NOT_SET_UP_PATH)
    redirect(loginErrorHref('callback_failed'))
  }

  // Get the stored redirect destination
  const cookieStore = await cookies()
  const redirectTo = validateRedirectUrl(cookieStore.get('oauth_redirect')?.value, '/')

  // Clean up redirect cookie
  cookieStore.delete('oauth_redirect')

  // Redirect to the final destination
  redirect(redirectTo)
}

// ============================================
// LOADING STATE
// ============================================

// This component is shown briefly while the server processes the callback
export function generateStaticParams() {
  return validProviders.map((provider) => ({
    provider,
  }))
}
