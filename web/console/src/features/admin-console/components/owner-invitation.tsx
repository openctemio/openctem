'use client'

import { useState } from 'react'
import { MailCheck, RotateCw, XCircle } from 'lucide-react'
import { toast } from 'sonner'
import { useTranslation } from '@/context/i18n-provider'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { RelativeTime } from '@/features/shared'
import { AdminApiError } from '@console/lib/admin-api/client'
import { cancelOwnerInvitation, resendOwnerInvitation } from '../api/use-admin-organizations'
import type { AdminOwnerInvitation, AdminOwnerInvitationStatus } from '../types'

/**
 * Ownership invitations in the console
 * (docs/architecture/organization-ownership-invitations.md): an organization
 * created for a person who already has an account waits, with no owner and
 * nobody in it, until that person accepts in the app. One badge, one notice
 * and one panel, used by the list, the create dialogs and the Users tab.
 */

function useStatusLabel() {
  const { t } = useTranslation()
  return (status: AdminOwnerInvitationStatus): string => {
    switch (status) {
      case 'pending':
        return t('admin.ownerInvitation.status.pending', 'Waiting for owner to accept')
      case 'expired':
        return t('admin.ownerInvitation.status.expired', 'Owner invitation expired')
      case 'declined':
        return t('admin.ownerInvitation.status.declined', 'Owner invitation declined')
      default:
        return t('admin.ownerInvitation.status.canceled', 'Owner invitation canceled')
    }
  }
}

/** The organization's ownership-invitation state as a badge. */
export function OwnerInvitationBadge({ invitation }: { invitation: AdminOwnerInvitation }) {
  const label = useStatusLabel()
  return (
    <Badge
      variant="outline"
      className={
        invitation.status === 'pending'
          ? 'border-info/50 text-info'
          : 'border-warning/50 text-warning'
      }
    >
      {label(invitation.status)}
    </Badge>
  )
}

/** Shown after a create request invited an existing account to own the organization. */
export function OwnerInvitationSentNotice({
  email,
  invitation,
}: {
  email: string
  invitation?: AdminOwnerInvitation
}) {
  const { t } = useTranslation()
  return (
    <Alert>
      <MailCheck className="size-4" aria-hidden="true" />
      <AlertDescription className="space-y-1">
        <p>
          {t(
            'admin.ownerInvitation.sent',
            "This person already has an account. They'll get an invitation to become the owner."
          )}
        </p>
        <p className="text-muted-foreground">
          {t(
            'admin.ownerInvitation.sentDetail',
            '{email} becomes the owner only after accepting in the app. Until then the organization has no owner and nobody can open it.',
            { email }
          )}
        </p>
        {invitation && (
          <p className="text-muted-foreground">
            {t('admin.ownerInvitation.expires', 'Expires')}{' '}
            <RelativeTime date={invitation.expires_at} />
          </p>
        )}
      </AlertDescription>
    </Alert>
  )
}

/**
 * The Users tab's view of a pending (or expired, declined, canceled)
 * invitation: who, when, and the administrator's actions. Changing the
 * invitee is the Create first owner dialog, passed in as `changeInvitee`.
 */
export function OwnerInvitationPanel({
  tenantId,
  invitation,
  canManage,
  changeInvitee,
  onChanged,
}: {
  tenantId: string
  invitation: AdminOwnerInvitation
  canManage: boolean
  changeInvitee?: React.ReactNode
  onChanged: () => void
}) {
  const { t } = useTranslation()
  const label = useStatusLabel()
  const [busy, setBusy] = useState(false)
  const [confirmCancel, setConfirmCancel] = useState(false)
  const open = invitation.status === 'pending' || invitation.status === 'expired'
  const resendReady =
    open &&
    invitation.resends_left > 0 &&
    (!invitation.resend_available_at || new Date(invitation.resend_available_at) <= new Date())

  const resend = async () => {
    setBusy(true)
    try {
      await resendOwnerInvitation(tenantId)
      toast.success(t('admin.ownerInvitation.resent', 'Invitation sent again'))
      onChanged()
    } catch (err) {
      toast.error(
        err instanceof AdminApiError
          ? err.message
          : t('admin.ownerInvitation.resendFailed', 'Could not send the invitation again')
      )
    } finally {
      setBusy(false)
    }
  }

  const cancel = async () => {
    try {
      await cancelOwnerInvitation(tenantId)
      toast.success(t('admin.ownerInvitation.canceledToast', 'Invitation canceled'))
      onChanged()
    } catch (err) {
      toast.error(
        err instanceof AdminApiError
          ? err.message
          : t('admin.ownerInvitation.cancelFailed', 'Could not cancel the invitation')
      )
    }
  }

  return (
    <div className="space-y-3 rounded-md border p-4 text-sm">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="space-y-1">
          <p className="font-medium">{label(invitation.status)}</p>
          {invitation.invitee_email && (
            <p className="text-muted-foreground">
              {t('admin.ownerInvitation.invitee', 'Invited: {email}', {
                email: invitation.invitee_email,
              })}
            </p>
          )}
        </div>
        <OwnerInvitationBadge invitation={invitation} />
      </div>
      <dl className="grid gap-x-6 gap-y-1 text-muted-foreground sm:grid-cols-3">
        <div>
          <dt className="text-xs">{t('admin.ownerInvitation.lastSent', 'Last sent')}</dt>
          <dd className="text-foreground">
            <RelativeTime date={invitation.last_sent_at} />
          </dd>
        </div>
        <div>
          <dt className="text-xs">{t('admin.ownerInvitation.expires', 'Expires')}</dt>
          <dd className="text-foreground">
            <RelativeTime date={invitation.expires_at} />
          </dd>
        </div>
        <div>
          <dt className="text-xs">{t('admin.ownerInvitation.sends', 'Sends left')}</dt>
          <dd className="text-foreground">{invitation.resends_left}</dd>
        </div>
      </dl>
      <p className="text-muted-foreground">
        {open
          ? t(
              'admin.ownerInvitation.pendingHelp',
              'The person accepts or declines in the app after signing in again. Until then the organization has no owner and nobody can open it.'
            )
          : t(
              'admin.ownerInvitation.closedHelp',
              'The organization still has no owner. Invite someone else, or create a new owner account.'
            )}
      </p>
      {canManage && (
        <div className="flex flex-wrap gap-2">
          {open && (
            <Button size="sm" variant="outline" disabled={busy || !resendReady} onClick={resend}>
              <RotateCw className="me-2 size-4" aria-hidden="true" />
              {t('admin.ownerInvitation.resend', 'Send again')}
            </Button>
          )}
          {changeInvitee}
          {open && (
            <Button size="sm" variant="outline" onClick={() => setConfirmCancel(true)}>
              <XCircle className="me-2 size-4" aria-hidden="true" />
              {t('admin.ownerInvitation.cancel', 'Cancel invitation')}
            </Button>
          )}
        </div>
      )}
      <ConfirmDialog
        open={confirmCancel}
        onOpenChange={setConfirmCancel}
        title={t('admin.ownerInvitation.cancelTitle', 'Cancel the invitation?')}
        desc={t(
          'admin.ownerInvitation.cancelDesc',
          'The person is told by email. The organization stays without an owner until you invite someone else or create its first owner.'
        )}
        confirmText={t('admin.ownerInvitation.cancel', 'Cancel invitation')}
        destructive
        handleConfirm={cancel}
      />
    </div>
  )
}
