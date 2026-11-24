'use client'

import { useEffect, useState } from 'react'
import { Building2, Check, Loader2, X } from 'lucide-react'
import { toast } from 'sonner'
import { navigateAfterSessionChange } from '@/lib/session-navigation'

import { ConfirmDialog } from '@/components/confirm-dialog'
import { EntryActions, EntryCard, EntryHeader } from '@/components/entry'
import { OrgAvatar } from '@/components/layout/org-avatar'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { useTranslation } from '@/context/i18n-provider'
import { RelativeTime } from '@/features/shared/components/relative-time'
import { useTenant } from '@/context/tenant-provider'
import {
  acceptOwnershipInvitation,
  declineOwnershipInvitation,
  useOwnershipInvitations,
  type OwnershipInvitation,
} from '../api/use-ownership-invitations'

/**
 * Organizations a platform administrator created for this account, waiting
 * for it to accept ownership. Accepting asks for a recent sign-in. Nothing
 * changes until the person accepts; declining leaves the organization to the
 * administrator. `hideWhenEmpty` lets My account show the card only when
 * there is something to answer.
 */
export function OwnershipInvitationsCard({
  hideWhenEmpty = false,
  surface = 'card',
}: {
  hideWhenEmpty?: boolean
  /** `entry`: the page's own card on /ownership-invitations (title is the page's h1). */
  surface?: 'card' | 'entry'
}) {
  const { t } = useTranslation()
  const { invitations, isLoading, mutate } = useOwnershipInvitations()
  const [busy, setBusy] = useState<string | null>(null)
  const [declining, setDeclining] = useState<OwnershipInvitation | null>(null)
  // After accepting, open the organization once it is in the account's list
  // (the organization switcher's own call).
  const { tenants, refreshTenants, switchTeam } = useTenant()
  const [openNext, setOpenNext] = useState<string | null>(null)
  useEffect(() => {
    if (!openNext || !tenants.some((m) => m.id === openNext)) return
    setOpenNext(null)
    void switchTeam(openNext).then(
      () => navigateAfterSessionChange('/', { replace: true }),
      () => window.location.reload()
    )
  }, [openNext, tenants, switchTeam])

  if (hideWhenEmpty && (isLoading || invitations.length === 0)) return null

  const accept = async (inv: OwnershipInvitation) => {
    setBusy(inv.id)
    try {
      await acceptOwnershipInvitation(inv.id)
      toast.success(
        t('account.ownershipInvitations.accepted', 'You now own {name}', {
          name: inv.organization_name,
        })
      )
      setOpenNext(inv.organization_id)
      await refreshTenants()
    } catch (err) {
      toast.error(
        err instanceof Error
          ? err.message
          : t('account.ownershipInvitations.acceptFailed', 'Could not accept the invitation')
      )
      void mutate()
    } finally {
      setBusy(null)
    }
  }

  const decline = async () => {
    if (!declining) return
    try {
      await declineOwnershipInvitation(declining.id)
      toast.success(t('account.ownershipInvitations.declined', 'Invitation declined'))
    } catch (err) {
      toast.error(
        err instanceof Error
          ? err.message
          : t('account.ownershipInvitations.declineFailed', 'Could not decline the invitation')
      )
    } finally {
      void mutate()
    }
  }

  const entry = surface === 'entry'
  // One filled button per screen: Accept is the filled action only when it is
  // the one choice; with several invitations no row outranks another.
  const single = invitations.length === 1
  const title = t('account.ownershipInvitations.title', 'Organizations waiting for you')
  const description = t(
    'account.ownershipInvitations.desc',
    'A platform administrator created these organizations for you. You become the owner only if you accept; you will be asked to confirm your identity.'
  )

  const body = isLoading ? (
    <Loader2 className="size-4 animate-spin text-muted-foreground" aria-hidden="true" />
  ) : invitations.length === 0 ? (
    <p className={entry ? 'text-body text-muted-foreground' : 'text-sm text-muted-foreground'}>
      {t('account.ownershipInvitations.empty', 'No invitations are waiting for you.')}
    </p>
  ) : (
    <ul className="divide-y">
      {invitations.map((inv) => (
        <li
          key={inv.id}
          className="flex flex-wrap items-center justify-between gap-3 py-3 first:pt-0 last:pb-0"
        >
          <div className="flex min-w-0 items-center gap-3">
            {entry ? (
              <OrgAvatar name={inv.organization_name} />
            ) : (
              <Building2 className="size-5 shrink-0 text-muted-foreground" aria-hidden="true" />
            )}
            <div className="min-w-0">
              <p className={entry ? 'text-body truncate font-medium' : 'truncate font-medium'}>
                {inv.organization_name}
              </p>
              <p
                className={
                  entry ? 'text-cap text-muted-foreground' : 'text-sm text-muted-foreground'
                }
              >
                {t('account.ownershipInvitations.expires', 'Expires')}{' '}
                <RelativeTime date={inv.expires_at} />
              </p>
            </div>
          </div>
          {entry ? (
            <EntryActions layout="row" className="max-sm:w-full">
              <Button variant="outline" disabled={busy !== null} onClick={() => setDeclining(inv)}>
                {t('account.ownershipInvitations.decline', 'Decline')}
              </Button>
              <Button
                variant={single ? 'signal' : 'outline'}
                disabled={busy !== null}
                onClick={() => void accept(inv)}
              >
                {busy === inv.id && <Loader2 className="size-4 animate-spin" aria-hidden="true" />}
                {t('account.ownershipInvitations.accept', 'Accept and become owner')}
              </Button>
            </EntryActions>
          ) : (
            <div className="flex gap-2">
              <Button
                size="sm"
                variant="outline"
                disabled={busy !== null}
                onClick={() => setDeclining(inv)}
              >
                <X className="size-4" aria-hidden="true" />
                {t('account.ownershipInvitations.decline', 'Decline')}
              </Button>
              <Button
                size="sm"
                variant={single ? 'default' : 'outline'}
                disabled={busy !== null}
                onClick={() => void accept(inv)}
              >
                {busy === inv.id ? (
                  <Loader2 className="size-4 animate-spin" aria-hidden="true" />
                ) : (
                  <Check className="size-4" aria-hidden="true" />
                )}
                {t('account.ownershipInvitations.accept', 'Accept and become owner')}
              </Button>
            </div>
          )}
        </li>
      ))}
    </ul>
  )

  const confirm = (
    <ConfirmDialog
      open={declining !== null}
      onOpenChange={(open) => !open && setDeclining(null)}
      title={t('account.ownershipInvitations.declineTitle', 'Decline the invitation?')}
      desc={t(
        'account.ownershipInvitations.declineDesc',
        'You will not become the owner of {name}. The platform administrator decides what happens to it.',
        { name: declining?.organization_name ?? '' }
      )}
      confirmText={t('account.ownershipInvitations.decline', 'Decline')}
      destructive
      handleConfirm={decline}
    />
  )

  if (entry) {
    return (
      <EntryCard aria-busy={isLoading || undefined}>
        <EntryHeader title={title} description={description} />
        {body}
        {confirm}
      </EntryCard>
    )
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>{title}</CardTitle>
        <CardDescription>{description}</CardDescription>
      </CardHeader>
      <CardContent>{body}</CardContent>
      {confirm}
    </Card>
  )
}
