/**
 * Link an organization's single sign-on to the signed-in account
 * (Account > Security, "Organization sign-in"). API design:
 * server/docs/architecture/sso-authentication.md, "Linking an existing account".
 *
 * The start sends the proof typed in the confirm dialog to the API from the
 * server, with the session cookie. The API's one-time browser binding never
 * reaches page JavaScript: it goes into an HttpOnly cookie with the state and
 * the link intent, and only the identity provider's URL goes back to the
 * browser. The provider returns to the SSO callback (the redirect address the
 * organization registered), which hands a link round trip to the SSO link
 * route; that route calls completeSSOLinkCallback. The API accepts the
 * completion only for this account and session, once, with this browser's
 * binding, and issues no session.
 */

'use server'

import { cookies } from 'next/headers'

import { env } from '@/lib/env'
import { browserContextHeaders } from '@/lib/api/browser-context-headers'
import { userEndpoints } from '@/lib/api/endpoints'
import { bindingCookieName, bindingCookieOptions } from '@/features/auth/lib/browser-binding'
import { SSO_LINK_INTENT_COOKIE } from '@/features/auth/lib/oauth-cookies'
import { isAllowedValue, sanitizeLogValue } from '@/lib/log-sanitize'
import type { LinkProof } from '@/features/auth/actions/social-auth-actions'

import type { SSOProviderType } from '../types/sso.types'

const SSO_PROVIDER_TYPES: readonly SSOProviderType[] = ['entra_id', 'okta', 'google_workspace']
const ORG_SLUG = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/
const MAX_PROOF_LENGTH = 1024

class SSOLinkBackendError extends Error {
  constructor(
    readonly code?: string,
    readonly status?: number
  ) {
    super(code ?? 'SSO link request failed')
    this.name = 'SSOLinkBackendError'
  }
}

async function backendFetch<T>(endpoint: string, accessToken: string, body: unknown): Promise<T> {
  const response = await fetch(`${env.api.url}${endpoint}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...(await browserContextHeaders()),
      Authorization: `Bearer ${accessToken}`,
    },
    body: JSON.stringify(body),
  })
  if (!response.ok) {
    const data = await response.json().catch(() => ({}))
    throw new SSOLinkBackendError(
      typeof data?.code === 'string' ? data.code : undefined,
      response.status
    )
  }
  return response.json()
}

/** The proof as the API reads it; anything malformed is no proof. */
function stepUpOf(proof: LinkProof): { totp: string } | { password: string } | undefined {
  if ('totp' in proof && typeof proof.totp === 'string' && proof.totp.length <= MAX_PROOF_LENGTH) {
    return { totp: proof.totp }
  }
  if (
    'password' in proof &&
    typeof proof.password === 'string' &&
    proof.password.length <= MAX_PROOF_LENGTH
  ) {
    return { password: proof.password }
  }
  return undefined
}

function callbackUrl(provider: SSOProviderType): string {
  return `${env.app.url}/auth/sso/callback/${provider}`
}

/** The result of starting a link: where to send the browser, or the API code on a refusal. */
export type SSOLinkStartResult =
  { success: true; authorizationUrl: string } | { success: false; code?: string; status?: number }

/** Start linking an organization's sign-in to the signed-in account. */
export async function startSSOLinkAction(
  org: string,
  provider: SSOProviderType,
  proof: LinkProof
): Promise<SSOLinkStartResult> {
  if (!isAllowedValue(SSO_PROVIDER_TYPES, provider)) return { success: false }
  if (typeof org !== 'string' || !ORG_SLUG.test(org)) return { success: false }
  const stepUp = proof ? stepUpOf(proof) : undefined
  if (!stepUp) return { success: false, code: 'LINK_PROOF_REQUIRED' }
  const cookieStore = await cookies()
  const accessToken = cookieStore.get(env.auth.cookieName)?.value
  if (!accessToken) return { success: false, code: 'SESSION_EXPIRED', status: 401 }
  let data: { authorization_url?: unknown; state?: unknown; browser_binding?: unknown }
  try {
    data = await backendFetch(userEndpoints.ssoLinkStart(provider), accessToken, {
      org,
      redirect_uri: callbackUrl(provider),
      step_up: stepUp,
    })
  } catch (error) {
    console.error('SSO link start error:', sanitizeLogValue(provider), error)
    return error instanceof SSOLinkBackendError
      ? { success: false, code: error.code, status: error.status }
      : { success: false }
  }
  const { authorization_url: url, state, browser_binding: binding } = data ?? {}
  if (
    typeof url !== 'string' ||
    !url.startsWith('https://') ||
    typeof state !== 'string' ||
    state.length === 0 ||
    state.length > 4096 ||
    typeof binding !== 'string' ||
    binding.length === 0 ||
    binding.length > 256
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
  cookieStore.set('sso_state', state, opts)
  cookieStore.set(SSO_LINK_INTENT_COOKIE, provider, opts)
  cookieStore.set(bindingCookieName('sso'), binding, bindingCookieOptions())
  cookieStore.delete('sso_redirect')
  return { success: true, authorizationUrl: url }
}

/** The result of a link completion: the API code on a refusal. */
export type SSOLinkCallbackResult = { success: true } | { success: false; code?: string }

/**
 * Finish a link after the identity provider's redirect: check the state
 * cookie, take the single-use browser binding, then let the API bind the
 * identity to the account of the session cookie.
 */
export async function completeSSOLinkCallback(
  provider: SSOProviderType,
  code: string,
  state: string
): Promise<SSOLinkCallbackResult> {
  if (!isAllowedValue(SSO_PROVIDER_TYPES, provider)) return { success: false }
  const cookieStore = await cookies()
  const storedState = cookieStore.get('sso_state')?.value
  cookieStore.delete('sso_state')
  cookieStore.delete(SSO_LINK_INTENT_COOKIE)
  const bindingName = bindingCookieName('sso')
  const browserBinding = cookieStore.get(bindingName)?.value
  cookieStore.delete(bindingName)
  if (!storedState || storedState !== state || !browserBinding) {
    return { success: false, code: 'SSO_INVALID_STATE' }
  }
  const accessToken = cookieStore.get(env.auth.cookieName)?.value
  if (!accessToken) return { success: false, code: 'SESSION_EXPIRED' }
  try {
    await backendFetch(userEndpoints.ssoLinkComplete(provider), accessToken, {
      code,
      state,
      browser_binding: browserBinding,
    })
    return { success: true }
  } catch (error) {
    console.error('SSO link callback error:', sanitizeLogValue(provider), error)
    return {
      success: false,
      code: error instanceof SSOLinkBackendError ? error.code : undefined,
    }
  }
}
