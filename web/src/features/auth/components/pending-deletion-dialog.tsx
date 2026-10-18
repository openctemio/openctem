'use client'

import { useState } from 'react'
import { Loader2 } from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { useTranslation } from '@/context/i18n-provider'
import { cancelOrganizationDeletionAction, type LoginTenant } from '../actions/local-auth-actions'

/**
 * Shown at sign-in to an owner of an organization that is scheduled for
 * deletion (api/docs/architecture/organization-deletion.md): the
 * organization is closed until then, and an owner can cancel. `onCancelled`
 * gets the organization that was reopened; `onContinue` goes on without it.
 */
export function PendingDeletionDialog({
  organizations,
  onCancelled,
  onContinue,
}: {
  organizations: LoginTenant[]
  onCancelled: (org: LoginTenant) => void
  onContinue: () => void
}) {
  const { t } = useTranslation()
  const [busy, setBusy] = useState<string | null>(null)

  const cancel = async (org: LoginTenant) => {
    setBusy(org.id)
    const res = await cancelOrganizationDeletionAction(org.id)
    setBusy(null)
    if (!res.success) {
      toast.error(
        res.error || t('auth.pendingDeletion.cancelFailed', 'Could not cancel the deletion')
      )
      return
    }
    toast.success(
      t('auth.pendingDeletion.cancelled', 'The deletion of {name} is cancelled.', {
        name: org.name,
      })
    )
    onCancelled(org)
  }

  return (
    <Dialog open onOpenChange={(open) => !open && onContinue()}>
      <DialogContent size="md">
        <DialogHeader>
          <DialogTitle>
            {t('auth.pendingDeletion.title', 'Organization scheduled for deletion')}
          </DialogTitle>
          <DialogDescription>
            {t(
              'auth.pendingDeletion.description',
              'It is closed to everyone until then. As an owner you can cancel the deletion; everything works again as before.'
            )}
          </DialogDescription>
        </DialogHeader>
        <DialogBody>
          <ul className="divide-y">
            {organizations.map((org) => (
              <li key={org.id} className="flex flex-wrap items-center justify-between gap-3 py-3">
                <div className="min-w-0">
                  <div className="truncate font-medium">{org.name}</div>
                  {org.deletion_due_at && (
                    <div className="text-sm text-muted-foreground">
                      {t('auth.pendingDeletion.due', 'Deleted on {date}', {
                        date: new Date(org.deletion_due_at).toLocaleString(),
                      })}
                    </div>
                  )}
                </div>
                <Button
                  size="sm"
                  variant="outline"
                  disabled={busy !== null}
                  onClick={() => void cancel(org)}
                >
                  {busy === org.id && <Loader2 className="me-2 size-4 animate-spin" />}
                  {t('auth.pendingDeletion.cancel', 'Cancel deletion')}
                </Button>
              </li>
            ))}
          </ul>
        </DialogBody>
        <DialogFooter>
          <Button variant="ghost" disabled={busy !== null} onClick={onContinue}>
            {t('auth.pendingDeletion.continue', 'Continue without it')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
