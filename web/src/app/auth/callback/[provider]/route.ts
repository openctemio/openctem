/**
 * OAuth callback (Google, GitHub, Microsoft).
 *
 * A Route Handler, not a page: finishing the sign-in writes cookies (the
 * session tokens, and clears the OAuth state), and Next.js only allows cookie
 * writes in a Route Handler or a Server Action. As a page every callback
 * failed with "Cookies can only be modified in a Server Action or Route
 * Handler" and the person landed back on /login.
 */

import { redirect } from 'next/navigation'
import { cookies } from 'next/headers'
import type { NextRequest } from 'next/server'

import {
  NOT_SET_UP_PATH,
  SIGNUP_NOT_AVAILABLE,
  SSO_REQUIRED,
} from '@/features/auth/lib/signup-outcome'
import { loginErrorCodeFor } from '@/features/auth/lib/auth-error-codes'
import { loginErrorHref } from '@/features/auth/lib/login-error'
import {
  completeLinkCallback,
  handleOAuthCallback,
  type SocialProvider,
} from '@/features/auth/actions/social-auth-actions'
import { OAUTH_LINK_INTENT_COOKIE } from '@/features/auth/lib/oauth-cookies'
import { linkResultHref } from '@/features/account/lib/link-result'
import { validateRedirectUrl } from '@/lib/redirect'

export const dynamic = 'force-dynamic'

const validProviders: SocialProvider[] = ['google', 'github', 'microsoft']

function isValidProvider(provider: string): provider is SocialProvider {
  return validProviders.includes(provider as SocialProvider)
}

export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ provider: string }> }
) {
  const { provider } = await params
  const search = request.nextUrl.searchParams
  const code = search.get('code')
  const state = search.get('state')

  if (!isValidProvider(provider)) redirect(loginErrorHref('invalid_provider'))
  // error_description is the provider's free text: never echo it on /login.
  if (search.get('error')) redirect(loginErrorHref('provider_error'))
  if (!code || !state) redirect(loginErrorHref('missing_params'))

  // Read where to go before the callback clears the cookie.
  const cookieStore = await cookies()
  const redirectTo = validateRedirectUrl(cookieStore.get('oauth_redirect')?.value, '/')

  // Linking a provider to the signed-in account (Account > Security).
  if (cookieStore.get(OAUTH_LINK_INTENT_COOKIE)?.value === provider) {
    const linked = await completeLinkCallback(provider, code, state)
    redirect(linkResultHref(provider, linked.success ? undefined : (linked.code ?? 'LINK_FAILED')))
  }

  const result = await handleOAuthCallback(provider, code, state)
  // A linked password account: the sign-in page asks for the second factor.
  if (result.success && 'mfaRequired' in result) redirect(`/login?mfa=${result.mfaPurpose}`)
  if (!result.success) {
    // The sign-up policy refused to create an account: the one "not set up"
    // page, whatever the reason.
    if (result.code === SIGNUP_NOT_AVAILABLE) redirect(NOT_SET_UP_PATH)
    // The address's domain requires its organization's SSO.
    if (result.code === SSO_REQUIRED) redirect('/login')
    redirect(loginErrorHref(loginErrorCodeFor(result.code)))
  }
  redirect(redirectTo)
}
