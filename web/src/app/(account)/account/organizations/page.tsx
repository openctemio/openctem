/**
 * /account/organizations: the person's organizations, invitations and new
 * organization (api RFC-141). Open to anyone signed in. A person with no
 * organization lands here (it replaces /welcome); one whom an organization
 * does not admit yet sees that organization's one next step here.
 */

import { cookies } from 'next/headers'
import { redirect } from 'next/navigation'

import { OrganizationsHub } from '@/features/account/components/organizations-hub'
import { readWelcomeNotice } from '@/lib/auth/refresh-failure'
import { env } from '@/lib/env'

type SearchParams = Record<string, string | string[] | undefined>

const first = (v: string | string[] | undefined) => (Array.isArray(v) ? v[0] : v)

export default async function OrganizationsPage({
  searchParams,
}: {
  searchParams: Promise<SearchParams>
}) {
  const jar = await cookies()
  const hasAccess = !!jar.get(env.auth.cookieName)?.value
  if (!hasAccess && !jar.get(env.auth.refreshCookieName)?.value) {
    redirect('/login?next=%2Faccount%2Forganizations')
  }
  // A browser with no organization open and no account session yet (only a
  // refresh token, or the token of a social sign-in) starts the account
  // session here. An organization session is never replaced by it.
  const needsSession =
    !jar.get(env.cookies.accountOnly)?.value && !jar.get(env.cookies.tenant)?.value
  // Why the account space opened (a refused refresh): a known value only.
  const sp = await searchParams
  const notice = readWelcomeNotice(first(sp.notice), first(sp.org))
  return <OrganizationsHub needsSession={needsSession} notice={notice} />
}
