/**
 * Finishes linking an organization's single sign-on to the signed-in account
 * (Account > Security). The identity provider returns to the SSO callback,
 * the redirect address the organization registered; when the round trip was
 * a link (the link intent cookie), the callback sends the code here. A Route
 * Handler, because finishing writes cookies (it spends the state, the
 * browser binding and the intent). The API binds the identity only for the
 * account and session that started the link; no session is issued.
 */

import { redirect } from 'next/navigation'
import type { NextRequest } from 'next/server'

import { completeSSOLinkCallback } from '@/features/sso/actions/sso-link-actions'
import { ssoLinkResultHref } from '@/features/account/lib/link-result'
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

  if (!isValidProvider(provider)) redirect(ssoLinkResultHref('INVALID_PROVIDER'))
  // error_description is the provider's free text: never echoed.
  if (search.get('error')) redirect(ssoLinkResultHref('SSO_PROVIDER_ERROR'))
  if (!code || !state) redirect(ssoLinkResultHref('SSO_INVALID_STATE'))

  const linked = await completeSSOLinkCallback(provider, code, state)
  redirect(ssoLinkResultHref(linked.success ? undefined : (linked.code ?? 'LINK_FAILED')))
}
