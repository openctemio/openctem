/**
 * /welcome: the account space hub (api RFC-141).
 *
 * For a signed-in person with no organization. A person who has an
 * organization selected belongs in the app, so they go there. A person who
 * holds only a refresh token (or a token of a social sign-in) first gets the
 * account-only token, which the hub asks for on load.
 */

import { cookies } from 'next/headers'
import { redirect } from 'next/navigation'

import { WelcomeHub } from '@/features/account/components/welcome-hub'
import { readWelcomeNotice } from '@/lib/auth/refresh-failure'
import { env } from '@/lib/env'

type SearchParams = Record<string, string | string[] | undefined>

const first = (v: string | string[] | undefined) => (Array.isArray(v) ? v[0] : v)

export default async function WelcomePage({
  searchParams,
}: {
  searchParams: Promise<SearchParams>
}) {
  const jar = await cookies()
  if (!jar.get(env.auth.cookieName)?.value && !jar.get(env.auth.refreshCookieName)?.value) {
    redirect('/login?next=%2Fwelcome')
  }
  if (jar.get(env.cookies.tenant)?.value) {
    redirect('/')
  }
  // Why the account space opened (a refused refresh): a known value only.
  const sp = await searchParams
  const notice = readWelcomeNotice(first(sp.notice), first(sp.org))
  return <WelcomeHub needsSession={!jar.get(env.cookies.accountOnly)?.value} notice={notice} />
}
