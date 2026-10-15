'use client'

import { useState } from 'react'
import { Crown, Loader2 } from 'lucide-react'
import { toast } from 'sonner'

import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { useTranslation } from '@/context/i18n-provider'
import { refreshSession } from '@/lib/api/client'
import { getErrorMessage } from '@/lib/api/error-handler'

import {
  acceptOwnershipTransfer,
  cancelOwnershipTransfer,
  declineOwnershipTransfer,
  type OwnershipTransfer,
} from '../api/use-ownership-transfer'
import { transferErrorKey } from '../lib/ownership-transfer'

function formatDate(iso: string, locale: string): string {
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return iso
  return d.toLocaleString(locale, { dateStyle: 'medium', timeStyle: 'short' })
}

/**
 * The open ownership transfer, for the two people in it (api RFC-095 §3.1):
 * the owner sees who was asked and can cancel; the member asked sees what
 * changes and accepts (signing in again) or declines.
 */
export function OwnershipTransferBanner({
  transfer,
  onChanged,
  reloadAfterAccept = true,
}: {
  transfer: OwnershipTransfer | null
  onChanged: () => void
  /** Reload the app after accepting so the new role takes effect everywhere. */
  reloadAfterAccept?: boolean
}) {
  const { t, locale } = useTranslation()
  const [busy, setBusy] = useState<'accept' | 'decline' | 'cancel' | null>(null)
  const [confirm, setConfirm] = useState<'accept' | 'decline' | 'cancel' | null>(null)

  if (!transfer) return null

  const expires = formatDate(transfer.expires_at, locale)
  const fromName = transfer.from_name || t('org.ownership.theOwner', 'The owner')
  const toName = transfer.to_name || t('org.ownership.aMember', 'the member')
  const roleLabel = t(`org.role.${transfer.previous_owner_role}`, transfer.previous_owner_role)

  const fail = (err: unknown, fallbackKey: string, fallback: string) => {
    const known = transferErrorKey(err)
    toast.error(
      known ? t(known.key, known.fallback) : getErrorMessage(err, t(fallbackKey, fallback))
    )
  }

  const run = async (action: 'accept' | 'decline' | 'cancel') => {
    setBusy(action)
    try {
      if (action === 'accept') {
        await acceptOwnershipTransfer()
        toast.success(t('org.ownership.toast.accepted', 'You are now the owner'))
        if (reloadAfterAccept) {
          // The new role is read on the next token; refresh it, then reload.
          await refreshSession()
          window.location.reload()
          return
        }
      } else if (action === 'decline') {
        await declineOwnershipTransfer()
        toast.success(t('org.ownership.toast.declined', 'Transfer declined'))
      } else {
        await cancelOwnershipTransfer()
        toast.success(t('org.ownership.toast.canceled', 'Transfer canceled'))
      }
      onChanged()
    } catch (err) {
      fail(err, 'org.ownership.error.action', 'Could not complete this action')
      onChanged()
    } finally {
      setBusy(null)
      setConfirm(null)
    }
  }

  const isNewOwner = transfer.viewer === 'new_owner'

  return (
    <>
      <Alert className="mt-5 border-warning/50 bg-warning/10" role="region" aria-live="polite">
        <Crown className="h-4 w-4 text-warning" aria-hidden />
        <AlertTitle>
          {isNewOwner
            ? t('org.ownership.banner.newOwnerTitle', '{name} asked you to become the owner', {
                name: fromName,
              })
            : t('org.ownership.banner.ownerTitle', 'Waiting for {name} to accept ownership', {
                name: toName,
              })}
        </AlertTitle>
        <AlertDescription>
          <p>
            {isNewOwner
              ? t(
                  'org.ownership.banner.newOwnerBody',
                  'As the owner you can delete the organization, make administrators and change its security settings. {from} becomes {role}. You will sign in again to accept. The request expires on {date}.',
                  { from: fromName, role: roleLabel, date: expires }
                )
              : t(
                  'org.ownership.banner.ownerBody',
                  'Nothing changes until they accept. When they do, you become {role}. The request expires on {date}.',
                  { role: roleLabel, date: expires }
                )}
          </p>
          {isNewOwner && transfer.make_internal && (
            <p className="mt-1">
              {t(
                'org.ownership.banner.becomesInternal',
                'You also become an internal member: your end of access is removed.'
              )}
            </p>
          )}
          <div className="mt-3 flex flex-wrap gap-2">
            {isNewOwner ? (
              <>
                <Button size="sm" onClick={() => setConfirm('accept')} disabled={!!busy}>
                  {busy === 'accept' && <Loader2 className="me-2 h-4 w-4 animate-spin" />}
                  {t('org.ownership.banner.accept', 'Accept ownership')}
                </Button>
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => setConfirm('decline')}
                  disabled={!!busy}
                >
                  {t('org.ownership.banner.decline', 'Decline')}
                </Button>
              </>
            ) : (
              <Button
                size="sm"
                variant="outline"
                onClick={() => setConfirm('cancel')}
                disabled={!!busy}
              >
                {t('org.ownership.banner.cancel', 'Cancel transfer')}
              </Button>
            )}
          </div>
        </AlertDescription>
      </Alert>

      <ConfirmDialog
        open={confirm !== null}
        onOpenChange={(open) => !open && setConfirm(null)}
        title={
          confirm === 'accept'
            ? t('org.ownership.confirm.acceptTitle', 'Become the owner?')
            : confirm === 'decline'
              ? t('org.ownership.confirm.declineTitle', 'Decline ownership?')
              : t('org.ownership.confirm.cancelTitle', 'Cancel the transfer?')
        }
        desc={
          confirm === 'accept'
            ? t(
                'org.ownership.confirm.acceptDesc',
                'You will be asked to sign in again. You become the owner and {from} becomes {role}.',
                { from: fromName, role: roleLabel }
              )
            : confirm === 'decline'
              ? t(
                  'org.ownership.confirm.declineDesc',
                  '{from} stays the owner and is told that you declined.',
                  { from: fromName }
                )
              : t(
                  'org.ownership.confirm.cancelDesc',
                  'You stay the owner. {name} is told that the request was canceled.',
                  { name: toName }
                )
        }
        confirmText={
          confirm === 'accept'
            ? t('org.ownership.banner.accept', 'Accept ownership')
            : confirm === 'decline'
              ? t('org.ownership.banner.decline', 'Decline')
              : t('org.ownership.banner.cancel', 'Cancel transfer')
        }
        destructive={confirm !== 'accept'}
        isLoading={!!busy}
        handleConfirm={() => (confirm ? run(confirm) : undefined)}
      />
    </>
  )
}
