import { cookies } from 'next/headers'

import { env } from '@/lib/env'

import { InvitationView } from './invitation-view'

/**
 * Public invitation page (/invitations#token=...). Readable without a
 * session: an invited person who has no account yet sees the invitation and
 * can sign in or create their account from here.
 *
 * The token is in the URL fragment, which the browser never sends to a server;
 * the page reads it on the client (features/auth/lib/invitation-token.ts).
 */
export default async function InvitationPage() {
  const cookieStore = await cookies()
  const hasSession = Boolean(
    cookieStore.get(env.auth.cookieName)?.value ||
    cookieStore.get(env.auth.refreshCookieName)?.value
  )
  return <InvitationView hasSession={hasSession} />
}
