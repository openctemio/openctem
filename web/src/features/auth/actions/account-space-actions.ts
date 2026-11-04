/**
 * Server Actions of the account space (/welcome): start the account-only
 * session, and decline an invitation. Accepting an invitation and listing the
 * offers stay in local-auth-actions.ts (onboardingAcceptAction,
 * onboardingOptionsAction).
 */

'use server'

import { cookies } from 'next/headers'

import { authEndpoints } from '@/lib/api/endpoints'
import { browserContextHeaders } from '@/lib/api/browser-context-headers'
import { env } from '@/lib/env'

import { requestAccountToken, storeAccountSession } from '../lib/account-session'

export type StartAccountSessionResult =
  { success: true } | { success: false; code: 'HAS_ORGANIZATION' | 'SESSION' | 'ERROR' }

/**
 * Gives the signed-in person an account-only access token (POST
 * /auth/account-token) when they hold only a refresh token, or a token that
 * has no organization (a social sign-in). A person who can open an
 * organization gets HAS_ORGANIZATION and is sent to the organization flow.
 */
export async function startAccountSessionAction(): Promise<StartAccountSessionResult> {
  const refreshToken = (await cookies()).get(env.auth.refreshCookieName)?.value
  if (!refreshToken) return { success: false, code: 'SESSION' }
  const result = await requestAccountToken(refreshToken)
  if (!result.ok) return { success: false, code: result.code }
  await storeAccountSession(result)
  return { success: true }
}

export type OnboardingDeclineResult =
  { success: true } | { success: false; code?: string; error: string }

/**
 * Declines an invitation offered by the account's own options list, by its
 * opaque reference (the API checks the reference again and audits the decline
 * in the inviting organization).
 */
export async function onboardingDeclineAction(ref: string): Promise<OnboardingDeclineResult> {
  const refreshToken = (await cookies()).get(env.auth.refreshCookieName)?.value
  if (!refreshToken) return { success: false, code: 'SESSION', error: 'session' }
  if (typeof ref !== 'string' || ref.length === 0 || ref.length > 512) {
    return { success: false, code: 'OFFER_UNAVAILABLE', error: 'invalid' }
  }
  try {
    const response = await fetch(`${env.api.url}${authEndpoints.onboardingDecline()}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...(await browserContextHeaders()) },
      body: JSON.stringify({ refresh_token: refreshToken, ref }),
    })
    if (!response.ok) {
      const body = await response.json().catch(() => ({}))
      return {
        success: false,
        code: typeof body.code === 'string' ? body.code : undefined,
        error: body.message || `HTTP ${response.status}`,
      }
    }
    return { success: true }
  } catch (error) {
    return { success: false, error: error instanceof Error ? error.message : 'error' }
  }
}
