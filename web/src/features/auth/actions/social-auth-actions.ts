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

import { env } from '@/lib/env'
import { browserContextHeaders } from '@/lib/api/browser-context-headers'
import { bindingCookieName, bindingCookieOptions } from '@/features/auth/lib/browser-binding'
import { setServerCookie } from '@/lib/cookies-server'
import { authEndpoints, userEndpoints } from '@/lib/api/endpoints'
import {
  MAX_PENDING_LINK_LENGTH,
  MFA_CHALLENGE_COOKIE,
  MFA_PURPOSES,
  OAUTH_LINK_INTENT_COOKIE,
  pendingLinkCookieName,
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
    readonly code?: string,
    /** The pending-link secret the API set as a cookie on a 409. */
    readonly pendingLink?: string,
    readonly status?: number
  ) {
    super(message)
    this.name = 'BackendError'
  }
}

/**
 * The pending-link secret from the API's Set-Cookie (it is never in the
 * body), whichever cookie name the API uses.
 */
function pendingLinkFromSetCookie(response: Response): string | undefined {
  const headers = response.headers as Headers & { getSetCookie?: () => string[] }
  const all = typeof headers.getSetCookie === 'function' ? headers.getSetCookie() : []
  for (const raw of all) {
    const m = /^(?:__Host-)?oauth_pending_link=([^;]*)/.exec(raw.trim())
    if (m && m[1]) return m[1]
  }
  return undefined
}

/**
 * Keep the pending link of a refused social sign-in (409
 * OAUTH_ACCOUNT_EXISTS) for this browser in an HttpOnly cookie, so the app
 * can ask to confirm the link once the person has signed in. The secret never
 * reaches page script.
 */
async function rememberPendingLink(error: unknown): Promise<void> {
  if (!(error instanceof BackendError) || error.code !== 'OAUTH_ACCOUNT_EXISTS') return
  const token = error.pendingLink
  if (!token || token.length > MAX_PENDING_LINK_LENGTH || !/^[A-Za-z0-9_-]+$/.test(token)) {
    return
  }
  const cookieStore = await cookies()
  cookieStore.set(pendingLinkCookieName(), token, {
    httpOnly: true,
    secure: process.env.SECURE_COOKIES !== 'false',
    sameSite: 'lax',
    maxAge: 600, // the API keeps the pending link 10 minutes
    path: '/',
  })
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
      typeof errorData.code === 'string' ? errorData.code : undefined,
      pendingLinkFromSetCookie(response),
      response.status
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
    await rememberPendingLink(error)
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
 * Start a social sign-in: set the state and browser-binding cookies and return
 * the provider authorization URL. The client navigates to it (a server-action
 * redirect() to an external URL makes the awaiting client call fail while the
 * page is already leaving, which showed a false error).
 */
export async function initiateSocialLogin(
  provider: SocialProvider,
  redirectTo?: string
): Promise<{ ok: true; url: string } | { ok: false }> {
  const result = await getOAuthAuthorizationUrl(provider, redirectTo)
  if (!result.success) return { ok: false }
  return { ok: true, url: result.data.authorizationUrl }
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

/** The result of starting a link: where to send the browser, or the API code on a refusal. */
export type LinkStartResult =
  { success: true; authorizationUrl: string } | { success: false; code?: string; status?: number }

/**
 * Start linking a provider (Account > Security). The proof typed in the confirm
 * dialog goes to POST /me/sign-in-method-links/{provider}/start from here, on
 * the server, with the session cookie. The API's one-time browser binding
 * never reaches page JavaScript: it is set in an HttpOnly cookie together with
 * the state and the link intent, and only the provider's authorization URL
 * (which carries the state, not the binding) goes back to the browser. The API
 * accepts the callback only for this account and session, once, and only with
 * this browser's binding.
 */
export async function startLinkAction(
  provider: SocialProvider,
  proof: LinkProof
): Promise<LinkStartResult> {
  if (!isAllowedValue(SOCIAL_PROVIDERS, provider)) return { success: false }
  const stepUp = linkProofBody(proof)
  // A malformed proof is never sent; the dialog shows the generic refusal.
  if (!stepUp) return { success: false, code: 'LINK_PROOF_REQUIRED' }
  const cookieStore = await cookies()
  const accessToken = cookieStore.get(env.auth.cookieName)?.value
  if (!accessToken) return { success: false, code: 'SESSION_EXPIRED', status: 401 }
  let data: OAuthAuthorizationResponse
  try {
    data = await backendFetch<OAuthAuthorizationResponse>(userEndpoints.identityLink(provider), {
      method: 'POST',
      headers: { Authorization: `Bearer ${accessToken}` },
      body: JSON.stringify({
        redirect_uri: `${env.app.url}/auth/callback/${provider}`,
        ...JSON.parse(stepUp),
      }),
    })
  } catch (error) {
    console.error('OAuth link start error:', sanitizeLogValue(provider), error)
    return error instanceof BackendError
      ? { success: false, code: error.code, status: error.status }
      : { success: false }
  }
  if (
    typeof data?.state !== 'string' ||
    data.state.length === 0 ||
    data.state.length > 4096 ||
    typeof data.browser_binding !== 'string' ||
    data.browser_binding.length === 0 ||
    data.browser_binding.length > 256 ||
    typeof data.authorization_url !== 'string' ||
    data.authorization_url.length === 0
  ) {
    return { success: false }
  }
  const opts = {
    httpOnly: true,
    secure: process.env.SECURE_COOKIES !== 'false',
    sameSite: 'lax' as const,
    maxAge: 600,
    path: '/',
  }
  cookieStore.set('oauth_state', data.state, opts)
  cookieStore.set(OAUTH_LINK_INTENT_COOKIE, provider, opts)
  cookieStore.set(bindingCookieName('oauth'), data.browser_binding, bindingCookieOptions())
  cookieStore.delete('oauth_redirect')
  return { success: true, authorizationUrl: data.authorization_url }
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

// ============================================
// PENDING LINK (confirmed after signing in)
// ============================================

/**
 * What confirming a sign-in method change asks for: the authenticator code,
 * the password, or nothing usable (the account must turn on two-factor
 * authentication first).
 */
export type LinkProofKind = 'totp' | 'password' | ''

/** The proof typed in the confirm dialog, sent as `step_up`. */
export type LinkProof = { totp: string } | { password: string }

/** The provider account waiting to be linked to the signed-in account. */
export type PendingLink = { provider: SocialProvider; email: string; proof: LinkProofKind }

/** Codes after which the same pending link may be confirmed again. */
const PENDING_LINK_RETRY_CODES = new Set(['LINK_PROOF_REQUIRED', 'LINK_PROOF_FAILED'])

const MAX_PROOF_LENGTH = 1024

/** The proof as the API reads it; anything malformed is sent as no proof. */
function linkProofBody(proof?: LinkProof): string | undefined {
  if (!proof) return undefined
  if ('totp' in proof && typeof proof.totp === 'string' && proof.totp.length <= MAX_PROOF_LENGTH) {
    return JSON.stringify({ step_up: { totp: proof.totp } })
  }
  if (
    'password' in proof &&
    typeof proof.password === 'string' &&
    proof.password.length <= MAX_PROOF_LENGTH
  ) {
    return JSON.stringify({ step_up: { password: proof.password } })
  }
  return undefined
}

/** The result of confirming a pending link: the API code on a refusal. */
export type PendingLinkResult = { success: true } | { success: false; code?: string }

const pendingLinkPath = {
  describe: userEndpoints.pendingLinkDescribe,
  confirm: userEndpoints.pendingLinkComplete,
  cancel: userEndpoints.pendingLinkCancel,
} as const

async function pendingLinkCall<T>(
  action: 'describe' | 'confirm' | 'cancel',
  body?: string
): Promise<{ ok: true; data: T } | { ok: false; code?: string } | null> {
  const cookieStore = await cookies()
  const name = pendingLinkCookieName()
  const token = cookieStore.get(name)?.value
  if (!token) return null
  if (token.length > MAX_PENDING_LINK_LENGTH || !/^[A-Za-z0-9_-]+$/.test(token)) {
    cookieStore.delete(name)
    return null
  }
  const accessToken = cookieStore.get(env.auth.cookieName)?.value
  if (!accessToken) return { ok: false, code: 'SESSION_EXPIRED' }
  try {
    const url = `${env.api.url}${pendingLinkPath[action]()}`
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${accessToken}`,
        ...(await browserContextHeaders()),
        // The API reads the secret from its cookie only (under the name its
        // own Secure setting picks, so both are sent).
        Cookie: `__Host-oauth_pending_link=${token}; oauth_pending_link=${token}`,
      },
      body,
    })
    if (!response.ok) {
      const body = await response.json().catch(() => ({}))
      return { ok: false, code: typeof body.code === 'string' ? body.code : undefined }
    }
    const data = response.status === 204 ? (undefined as T) : ((await response.json()) as T)
    return { ok: true, data }
  } catch (error) {
    console.error('Pending link call failed:', action, error)
    return { ok: false }
  }
}

/**
 * The pending link of this browser, when it belongs to the signed-in account.
 * A pending link the API refuses (expired, used, another account's) is
 * forgotten.
 */
export async function getPendingLinkAction(): Promise<PendingLink | null> {
  const res = await pendingLinkCall<{ provider: string; email: string; proof?: string }>('describe')
  if (!res) return null
  if (!res.ok) {
    if (res.code !== 'SESSION_EXPIRED') (await cookies()).delete(pendingLinkCookieName())
    return null
  }
  if (!isAllowedValue(SOCIAL_PROVIDERS, res.data.provider)) return null
  const proof: LinkProofKind =
    res.data.proof === 'totp' || res.data.proof === 'password' ? res.data.proof : ''
  return { provider: res.data.provider, email: res.data.email, proof }
}

/**
 * Link the pending provider account to the signed-in account with the proof
 * typed in the confirm dialog (the authenticator code, else the password; the
 * sign-in that just happened does not count). The cookie stays only when the
 * proof was missing or wrong, so the person can type it again.
 */
export async function confirmPendingLinkAction(proof?: LinkProof): Promise<PendingLinkResult> {
  const res = await pendingLinkCall<unknown>('confirm', linkProofBody(proof))
  if (!res) return { success: false, code: 'PENDING_LINK_INVALID' }
  if (res.ok || !PENDING_LINK_RETRY_CODES.has(res.code ?? '')) {
    ;(await cookies()).delete(pendingLinkCookieName())
  }
  return res.ok ? { success: true } : { success: false, code: res.code }
}

/** "Not now": drop the pending link here and at the API. */
export async function dismissPendingLinkAction(): Promise<void> {
  await pendingLinkCall<unknown>('cancel')
  ;(await cookies()).delete(pendingLinkCookieName())
}
