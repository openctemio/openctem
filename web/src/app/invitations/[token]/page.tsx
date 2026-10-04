import { redirect } from 'next/navigation'

import { INVITATION_PAGE } from '@/features/auth/lib/invitation-token'

/**
 * Invitation links sent before the token moved to the URL fragment
 * (/invitations/{token}). They keep working: the token moves into the
 * fragment of /invitations, which the browser never sends to a server, and the
 * redirect replaces this URL in the history.
 */
export default async function LegacyInvitationPage({
  params,
}: {
  params: Promise<{ token: string }>
}) {
  const { token } = await params
  redirect(`${INVITATION_PAGE}#token=${encodeURIComponent(token)}`)
}
