/**
 * Organization SSO callback (Microsoft Entra ID, Okta, Google Workspace).
 *
 * A Route Handler, not a page: finishing the sign-in writes cookies (the
 * session tokens, and clears the SSO state, browser binding and return path),
 * and Next.js allows cookie writes only in a Route Handler or a Server Action.
 * As a page, the first cookie write threw "Cookies can only be modified in a
 * Server Action or Route Handler" and every organization SSO sign-in landed
 * back on /login.
 */

import { redirect } from 'next/navigation'
import { cookies } from 'next/headers'
import type { NextRequest } from 'next/server'

import { bindingCookieName } from '@/features/auth/lib/browser-binding'
import { loginErrorCodeFor } from '@/features/auth/lib/auth-error-codes'
import { loginErrorHref } from '@/features/auth/lib/login-error'
import { handleSSOCallback } from '@/features/sso/actions/sso-auth-actions'
import { validateRedirectUrl } from '@/lib/redirect'
import type { SSOProviderType } from '@/features/sso/types/sso.types'

export const dynamic = 'force-dynamic'

const validProviders: SSOProviderType[] = ['entra_id', 'okta', 'google_workspace']

function isValidProvider(provider: string): provider is SSOProviderType {
  return validProviders.includes(provider as SSOProviderType)
}

export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ provider: string }> }
) {
  const { provider } = await params
  const search = request.nextUrl.searchParams
  const code = search.get('code')
  const state = search.get('state')

  // Read the organization and the return path before the callback clears them.
  const cookieStore = await cookies()
  const orgSlug = cookieStore.get('sso_org')?.value || ''
  const org = orgSlug ? { org: orgSlug } : undefined
  const redirectTo = validateRedirectUrl(cookieStore.get('sso_redirect')?.value, '/')

  // These exits come before the callback action, which clears the attempt's
  // single-use cookies itself, so clear them here.
  const clearAttempt = () => {
    cookieStore.delete('sso_state')
    cookieStore.delete('sso_redirect')
    cookieStore.delete(bindingCookieName('sso'))
  }
  if (!isValidProvider(provider)) {
    clearAttempt()
    redirect(loginErrorHref('invalid_provider', org))
  }
  // error_description is the provider's free text: never echo it on /login.
  if (search.get('error')) {
    clearAttempt()
    redirect(loginErrorHref('provider_error', org))
  }
  if (!code || !state) {
    clearAttempt()
    redirect(loginErrorHref('missing_params', org))
  }

  const result = await handleSSOCallback(provider, code, state)
  if (!result.success) {
    // The API's code picks the message (waiting for approval, not a member,
    // no seat, ...), never its text.
    redirect(loginErrorHref(loginErrorCodeFor(result.code), org))
  }
  cookieStore.delete('sso_org')
  redirect(redirectTo)
}
