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
import { env } from '@/lib/env'

export default async function WelcomePage() {
  const jar = await cookies()
  if (!jar.get(env.auth.cookieName)?.value && !jar.get(env.auth.refreshCookieName)?.value) {
    redirect('/login?next=%2Fwelcome')
  }
  if (jar.get(env.cookies.tenant)?.value) {
    redirect('/')
  }
  return <WelcomeHub needsSession={!jar.get(env.cookies.accountOnly)?.value} />
}
