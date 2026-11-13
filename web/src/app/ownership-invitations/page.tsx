import type { Metadata } from 'next'

import { StepUpDialogHost } from '@/components/step-up-dialog'
import { TenantProvider } from '@/context/tenant-provider'
import { OwnershipInvitationsCard } from '@/features/account/components/ownership-invitations-card'

export const metadata: Metadata = {
  title: 'Ownership invitations',
  robots: { index: false, follow: false },
}

/**
 * /ownership-invitations: the page the ownership-invitation email links to.
 * It needs a signed-in session (the proxy sends the person to sign in and
 * back here) but no organization: an account that belongs to none can open
 * it (API docs: architecture/organization-ownership-invitations.md).
 */
export default function OwnershipInvitationsPage() {
  return (
    <TenantProvider>
      <div
        data-control-scale="entry"
        className="flex min-h-screen items-center justify-center bg-muted/30 p-4"
      >
        <div className="w-full max-w-xl">
          <OwnershipInvitationsCard />
        </div>
        {/* Accepting needs a recent sign-in. */}
        <StepUpDialogHost />
      </div>
    </TenantProvider>
  )
}
