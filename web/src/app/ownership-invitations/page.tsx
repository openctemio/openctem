import type { Metadata } from 'next'

import { EntryFrame } from '@/components/entry'
import { StepUpDialogHost } from '@/components/step-up-dialog'
import { TenantProvider } from '@/context/tenant-provider'
import { OwnershipInvitationsCard } from '@/features/account/components/ownership-invitations-card'
import { legalConfig } from '@/lib/legal'
import { legalSettings } from '@/lib/legal-settings'

export const metadata: Metadata = {
  title: 'Ownership invitations',
  robots: { index: false, follow: false },
}

/**
 * /ownership-invitations: the page the ownership-invitation email links to.
 * It needs a signed-in session (the proxy sends the person to sign in and
 * back here) but no organization: an account that belongs to none can open
 * it (API docs: architecture/organization-ownership-invitations.md).
 * It lists things, so it uses the wide entry column.
 */
export default async function OwnershipInvitationsPage() {
  const legal = legalConfig(await legalSettings())
  return (
    <TenantProvider>
      <EntryFrame width="wide" termsUrl={legal.termsUrl} privacyUrl={legal.privacyUrl}>
        <OwnershipInvitationsCard surface="entry" />
      </EntryFrame>
      {/* Accepting needs a recent sign-in. */}
      <StepUpDialogHost />
    </TenantProvider>
  )
}
