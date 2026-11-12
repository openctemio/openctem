'use client'

import { usePathname } from 'next/navigation'
import { Building2 } from 'lucide-react'

import Link from '@/components/link'
import { Button } from '@/components/ui/button'
import { useTranslation } from '@/context/i18n-provider'
import { cn } from '@/lib/utils'

import { useOwnershipInvitations } from '../api/use-ownership-invitations'

export const OWNERSHIP_INVITATIONS_HREF = '/ownership-invitations'

/**
 * Tells a signed-in account, wherever it lands (the organization shell, or the
 * account shell of a person with no organization), that an organization is waiting for it to accept
 * ownership (API docs: architecture/organization-ownership-invitations.md).
 * The invitation email is the only other pointer, and an installation without
 * email never sends it. Hidden on the invitations page itself and when there
 * is nothing to answer; the decision happens on that page (with step-up).
 */
export function OwnershipInvitationBanner({
  className,
  enabled = true,
}: {
  className?: string
  /** False while the browser has no session that can read the list yet. */
  enabled?: boolean
}) {
  const { t } = useTranslation()
  const pathname = usePathname()
  const { invitations } = useOwnershipInvitations(enabled)
  if (invitations.length === 0 || pathname === OWNERSHIP_INVITATIONS_HREF) return null

  const text =
    invitations.length === 1
      ? t(
          'account.ownershipInvitations.banner.one',
          'A platform administrator created {name} for you. You become its owner when you accept.',
          { name: invitations[0].organization_name }
        )
      : t(
          'account.ownershipInvitations.banner.many',
          '{count} organizations created for you are waiting for you to accept ownership.',
          { count: invitations.length }
        )

  return (
    <div
      role="status"
      data-testid="ownership-invitation-banner"
      className={cn(
        'flex flex-col gap-2 rounded-md border border-info/40 bg-info/10 px-3 py-2 text-sm sm:flex-row sm:items-center',
        className
      )}
    >
      <div className="flex min-w-0 flex-1 items-start gap-3">
        <Building2 className="mt-0.5 size-4 shrink-0" aria-hidden="true" />
        <p className="min-w-0 flex-1 break-words">{text}</p>
      </div>
      <Button asChild size="sm" variant="outline" className="self-start sm:self-auto">
        <Link href={OWNERSHIP_INVITATIONS_HREF}>
          {t('account.ownershipInvitations.banner.review', 'Review invitation')}
        </Link>
      </Button>
    </div>
  )
}
