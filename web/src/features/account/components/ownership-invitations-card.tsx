'use client'

import { useEffect, useState } from 'react'
import { Building2, Check, Loader2, X } from 'lucide-react'
import { toast } from 'sonner'
import { navigateAfterSessionChange } from '@/lib/session-navigation'

import { ConfirmDialog } from '@/components/confirm-dialog'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { useTranslation } from '@/context/i18n-provider'
import { RelativeTime } from '@/features/shared'
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
export function OwnershipInvitationsCard({ hideWhenEmpty = false }: { hideWhenEmpty?: boolean }) {
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

  return (
    <Card>
      <CardHeader>
        <CardTitle>
          {t('account.ownershipInvitations.title', 'Organizations waiting for you')}
        </CardTitle>
        <CardDescription>
          {t(
            'account.ownershipInvitations.desc',
            'A platform administrator created these organizations for you. You become the owner only if you accept; you will be asked to confirm your identity.'
          )}
        </CardDescription>
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <Loader2 className="size-4 animate-spin text-muted-foreground" aria-hidden="true" />
        ) : invitations.length === 0 ? (
          <p className="text-sm text-muted-foreground">
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
                  <Building2 className="size-5 shrink-0 text-muted-foreground" aria-hidden="true" />
                  <div className="min-w-0">
                    <p className="truncate font-medium">{inv.organization_name}</p>
                    <p className="text-sm text-muted-foreground">
                      {t('account.ownershipInvitations.expires', 'Expires')}{' '}
                      <RelativeTime date={inv.expires_at} />
                    </p>
                  </div>
                </div>
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
                  <Button size="sm" disabled={busy !== null} onClick={() => void accept(inv)}>
                    {busy === inv.id ? (
                      <Loader2 className="size-4 animate-spin" aria-hidden="true" />
                    ) : (
                      <Check className="size-4" aria-hidden="true" />
                    )}
                    {t('account.ownershipInvitations.accept', 'Accept and become owner')}
                  </Button>
                </div>
              </li>
            ))}
          </ul>
        )}
      </CardContent>
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
    </Card>
  )
}
