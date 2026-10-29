/**
 * Social Auth Server Actions
 *
 * Server-side actions for OAuth/Social authentication
 * Supports: Google, GitHub, Microsoft (EntraID)
 *
 * Flow:
 * 1. Frontend calls getOAuthAuthorizationUrl() to get the OAuth URL
 * 2. Frontend redirects user to that URL
 * 3. User authenticates with the provider
 * 4. Provider redirects to backend callback URL
 * 5. Backend exchanges code for tokens, creates/finds user, generates JWT
 * 6. Backend redirects to frontend callback with tokens in cookies
 */

'use server'

import { cookies } from 'next/headers'
import { redirect } from 'next/navigation'
import { loginErrorHref } from '@/features/auth/lib/login-error'

import { env } from '@/lib/env'
import { browserContextHeaders } from '@/lib/api/browser-context-headers'
import { bindingCookieName, bindingCookieOptions } from '@/features/auth/lib/browser-binding'
import { setServerCookie } from '@/lib/cookies-server'
import { authEndpoints, userEndpoints } from '@/lib/api/endpoints'
import {
  MFA_CHALLENGE_COOKIE,
  MFA_PURPOSES,
  OAUTH_LINK_INTENT_COOKIE,
} from '@/features/auth/lib/oauth-cookies'
import { validateRedirectUrl } from '@/lib/redirect'
import { isAllowedValue, sanitizeLogValue } from '@/lib/log-sanitize'

import type { AuthSuccessResponse, AuthErrorResponse } from '../schemas/auth.schema'

// ============================================
// TYPES
// ============================================

export type SocialProvider = 'google' | 'github' | 'microsoft'

// Server Action arguments come straight from the client: the provider is
// checked against this list before it is put into a backend URL path.
const SOCIAL_PROVIDERS: readonly SocialProvider[] = ['google', 'github', 'microsoft']
const UNSUPPORTED_PROVIDER: AuthErrorResponse = {
  success: false,
  error: 'Unsupported sign-in provider',
}

export interface OAuthUser {
  id: string
  email: string
  name: string
  firstName?: string
  lastName?: string
  avatar?: string
  roles: string[]
  emailVerified: boolean
  authProvider: SocialProvider
}

export interface OAuthAuthorizationResponse {
  authorization_url: string
  state: string
  /** One-time secret kept in an HttpOnly cookie and sent back with the callback. */
  browser_binding: string
}

export interface OAuthCallbackResult {
  access_token: string
  refresh_token: string
  expires_in: number
  token_type: string
  user: OAuthUser
}

/**
 * The callback's answer for a password account reached through a linked
 * provider that needs its second factor: no session yet.
 */
interface OAuthMfaChallenge {
  mfa_required: true
  mfa_token: string
  mfa_purpose: (typeof MFA_PURPOSES)[number]
  expires_in: number
}

/** A sign-in that waits for its second factor (the sign-in page asks for it). */
export interface OAuthMfaPending {
  success: true
  mfaRequired: true
  mfaPurpose: (typeof MFA_PURPOSES)[number]
}

// ============================================
// HELPER FUNCTIONS
// ============================================

/** A refused backend call, with the API's error code when it sent one. */
class BackendError extends Error {
  constructor(
    message: string,
    readonly code?: string
  ) {
    super(message)
    this.name = 'BackendError'
  }
}

async function backendFetch<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
  const url = `${env.api.url}${endpoint}`

  const response = await fetch(url, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...(await browserContextHeaders()),
      ...options.headers,
    },
  })

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({ message: response.statusText }))
    throw new BackendError(
      errorData.message || errorData.error || `HTTP ${response.status}`,
      typeof errorData.code === 'string' ? errorData.code : undefined
    )
  }

  return response.json()
}

// ============================================
// GET OAUTH AUTHORIZATION URL
// ============================================

/**
 * Get OAuth authorization URL for a provider
 * This URL will redirect the user to the OAuth provider
 */
export async function getOAuthAuthorizationUrl(
  provider: SocialProvider,
  redirectTo?: string
): Promise<AuthSuccessResponse<{ authorizationUrl: string; state: string }> | AuthErrorResponse> {
  if (!isAllowedValue(SOCIAL_PROVIDERS, provider)) return UNSUPPORTED_PROVIDER

  try {
    // Build the callback URL that the OAuth provider will redirect to
    const frontendCallbackUrl = `${env.app.url}/auth/callback/${provider}`

    // Call backend to get the authorization URL
    const data = await backendFetch<OAuthAuthorizationResponse>(
      `${authEndpoints.oauthAuthorize(provider)}?redirect_uri=${encodeURIComponent(frontendCallbackUrl)}&final_redirect=${encodeURIComponent(redirectTo || '/')}`,
      {
        method: 'GET',
      }
    )

    // Store state in cookie for CSRF protection verification
    const cookieStore = await cookies()
    // A sign-in, not a link: drop a link intent left by an abandoned link.
    cookieStore.delete(OAUTH_LINK_INTENT_COOKIE)
    cookieStore.set('oauth_state', data.state, {
      httpOnly: true,
      secure: process.env.SECURE_COOKIES !== 'false',
      sameSite: 'lax',
      maxAge: 600, // 10 minutes
      path: '/',
    })

    // Browser binding: the API refuses the callback without this secret.
    cookieStore.set(bindingCookieName('oauth'), data.browser_binding, bindingCookieOptions())

    // Store the final redirect destination (validated to prevent open redirect)
    if (redirectTo) {
      cookieStore.set('oauth_redirect', validateRedirectUrl(redirectTo, '/'), {
        httpOnly: true,
        secure: process.env.SECURE_COOKIES !== 'false',
        sameSite: 'lax',
        maxAge: 600, // 10 minutes
        path: '/',
      })
    }

    return {
      success: true,
      data: {
        authorizationUrl: data.authorization_url,
        state: data.state,
      },
    }
  } catch (error) {
    console.error('OAuth authorization error:', sanitizeLogValue(provider), error)
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Failed to get authorization URL',
    }
  }
}

// ============================================
// HANDLE OAUTH CALLBACK
// ============================================

/**
 * Handle OAuth callback from provider
 * This is called after the user authenticates with the OAuth provider
 */
export async function handleOAuthCallback(
  provider: SocialProvider,
  code: string,
  state: string
): Promise<AuthSuccessResponse<OAuthUser> | OAuthMfaPending | AuthErrorResponse> {
  if (!isAllowedValue(SOCIAL_PROVIDERS, provider)) return UNSUPPORTED_PROVIDER

  try {
    const cookieStore = await cookies()

    // Verify state to prevent CSRF attacks
    const storedState = cookieStore.get('oauth_state')?.value
    if (!storedState || storedState !== state) {
      return {
        success: false,
        error: 'Invalid OAuth state. Please try again.',
      }
    }

    // Clear the state cookie
    cookieStore.delete('oauth_state')

    // The binding is single use; a missing one is refused by the API too.
    const bindingName = bindingCookieName('oauth')
    const browserBinding = cookieStore.get(bindingName)?.value
    cookieStore.delete(bindingName)
    if (!browserBinding) {
      return {
        success: false,
        error: 'Invalid OAuth state. Please try again.',
      }
    }

    // Get the final redirect destination (stored for use after token exchange)
    const _redirectTo = cookieStore.get('oauth_redirect')?.value || '/'
    cookieStore.delete('oauth_redirect')

    // Exchange authorization code for tokens via backend
    const answer = await backendFetch<OAuthCallbackResult | OAuthMfaChallenge>(
      authEndpoints.oauthCallback(provider),
      {
        method: 'POST',
        body: JSON.stringify({
          code,
          state,
          redirect_uri: `${env.app.url}/auth/callback/${provider}`,
          browser_binding: browserBinding,
        }),
      }
    )

    // A password account reached through a linked provider: the same second
    // step as its password sign-in. The challenge stays in an httpOnly cookie
    // and the sign-in page asks for the code.
    if ('mfa_required' in answer && answer.mfa_required) {
      if (!isAllowedValue(MFA_PURPOSES, answer.mfa_purpose)) {
        return { success: false, error: 'Unexpected sign-in step' }
      }
      await setServerCookie(MFA_CHALLENGE_COOKIE, answer.mfa_token, {
        httpOnly: true,
        secure: process.env.SECURE_COOKIES !== 'false',
        sameSite: 'strict',
        maxAge: Math.max(1, answer.expires_in || 300),
        path: '/',
      })
      return { success: true, mfaRequired: true, mfaPurpose: answer.mfa_purpose }
    }
    const data = answer as OAuthCallbackResult

    // Store tokens in HttpOnly cookies
    await setServerCookie(env.auth.cookieName, data.access_token, {
      httpOnly: true,
      secure: process.env.SECURE_COOKIES !== 'false',
      sameSite: 'lax',
      maxAge: data.expires_in || 900, // Default 15 minutes
      path: '/',
    })

    if (data.refresh_token) {
      await setServerCookie(env.auth.refreshCookieName, data.refresh_token, {
        httpOnly: true,
        secure: process.env.SECURE_COOKIES !== 'false',
        sameSite: 'lax',
        maxAge: 7 * 24 * 60 * 60, // 7 days
        path: '/',
      })
    }

    return {
      success: true,
      data: data.user,
      message: `Successfully signed in with ${provider}`,
    }
  } catch (error) {
    console.error('OAuth callback error:', sanitizeLogValue(provider), error)
    return {
      success: false,
      error: error instanceof Error ? error.message : 'OAuth authentication failed',
      code: error instanceof BackendError ? error.code : undefined,
    }
  }
}

// ============================================
// INITIATE SOCIAL LOGIN
// ============================================

/**
 * Initiate social login by redirecting to OAuth provider
 * This is a convenience function that combines getting the URL and redirecting
 */
export async function initiateSocialLogin(
  provider: SocialProvider,
  redirectTo?: string
): Promise<never> {
  const result = await getOAuthAuthorizationUrl(provider, redirectTo)

  if (!result.success) {
    // If we can't get the authorization URL, redirect back to the login page
    // with an error code; the login form shows the matching message.
    redirect(loginErrorHref('start_failed'))
  }

  redirect(result.data.authorizationUrl)
}

// ============================================
// GET AVAILABLE PROVIDERS
// ============================================

export interface ProviderInfo {
  id: SocialProvider
  name: string
  enabled: boolean
}

/**
 * Get list of available OAuth providers from backend
 */
export async function getAvailableProviders(): Promise<
  AuthSuccessResponse<ProviderInfo[]> | AuthErrorResponse
> {
  try {
    const data = await backendFetch<{ providers: ProviderInfo[] }>(`${authEndpoints.info()}`, {
      method: 'GET',
    })

    return {
      success: true,
      data: data.providers || [],
    }
  } catch {
    // If backend doesn't support this endpoint, return default providers
    return {
      success: true,
      data: [
        { id: 'google', name: 'Google', enabled: true },
        { id: 'github', name: 'GitHub', enabled: true },
        { id: 'microsoft', name: 'Microsoft', enabled: true },
      ],
    }
  }
}

// ============================================
// LINK A PROVIDER TO THE SIGNED-IN ACCOUNT
// ============================================

/**
 * Keep the state of a link the browser started (Account > Security) for the
 * callback: the same state and browser-binding cookies a sign-in uses, plus
 * the link intent. The state came from POST /me/sign-in-method-links/{provider}/start,
 * which already required a fresh step-up; the API accepts it only for this
 * account and this session, once, and only with this browser's binding.
 */
export async function rememberLinkState(
  provider: SocialProvider,
  state: string,
  browserBinding: string
): Promise<{ success: boolean }> {
  if (!isAllowedValue(SOCIAL_PROVIDERS, provider)) return { success: false }
  if (typeof state !== 'string' || state.length === 0 || state.length > 4096) {
    return { success: false }
  }
  if (
    typeof browserBinding !== 'string' ||
    browserBinding.length === 0 ||
    browserBinding.length > 256
  ) {
    return { success: false }
  }
  const cookieStore = await cookies()
  const opts = {
    httpOnly: true,
    secure: process.env.SECURE_COOKIES !== 'false',
    sameSite: 'lax' as const,
    maxAge: 600,
    path: '/',
  }
  cookieStore.set('oauth_state', state, opts)
  cookieStore.set(OAUTH_LINK_INTENT_COOKIE, provider, opts)
  // Browser binding: the API refuses the link callback without this secret.
  cookieStore.set(bindingCookieName('oauth'), browserBinding, bindingCookieOptions())
  cookieStore.delete('oauth_redirect')
  return { success: true }
}

/** The result of a link callback: the API code on a refusal. */
export type LinkCallbackResult = { success: true } | { success: false; code?: string }

/**
 * Finish a link after the provider's redirect: check the state cookie, take
 * the single-use browser binding, then let the API bind the identity to the
 * account of the session cookie.
 */
export async function completeLinkCallback(
  provider: SocialProvider,
  code: string,
  state: string
): Promise<LinkCallbackResult> {
  if (!isAllowedValue(SOCIAL_PROVIDERS, provider)) return { success: false }
  const cookieStore = await cookies()
  const storedState = cookieStore.get('oauth_state')?.value
  cookieStore.delete('oauth_state')
  cookieStore.delete(OAUTH_LINK_INTENT_COOKIE)
  // The binding is single use; a missing one is refused by the API too.
  const bindingName = bindingCookieName('oauth')
  const browserBinding = cookieStore.get(bindingName)?.value
  cookieStore.delete(bindingName)
  if (!storedState || storedState !== state || !browserBinding) {
    return { success: false, code: 'OAUTH_INVALID_STATE' }
  }
  const accessToken = cookieStore.get(env.auth.cookieName)?.value
  if (!accessToken) return { success: false, code: 'SESSION_EXPIRED' }
  try {
    await backendFetch<unknown>(userEndpoints.identityLinkCallback(provider), {
      method: 'POST',
      headers: { Authorization: `Bearer ${accessToken}` },
      body: JSON.stringify({
        code,
        state,
        redirect_uri: `${env.app.url}/auth/callback/${provider}`,
        browser_binding: browserBinding,
      }),
    })
    return { success: true }
  } catch (error) {
    console.error('OAuth link callback error:', sanitizeLogValue(provider), error)
    return { success: false, code: error instanceof BackendError ? error.code : undefined }
  }
}
