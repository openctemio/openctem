'use client'

import { useState } from 'react'
import { Check, Copy, MailCheck, MailX, RotateCw, XCircle } from 'lucide-react'
import { toast } from 'sonner'
import { useTranslation } from '@/context/i18n-provider'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { RelativeTime } from '@/features/shared'
import { copyToClipboard } from '@/lib/clipboard'
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

/**
 * The web app address where the invitee accepts, with a Copy button. Not a
 * secret: the invitation is bound to the account, so the page shows it to
 * the invitee only, after they sign in.
 */
export function OwnerInvitationAcceptAddress({ url }: { url?: string }) {
  const { t } = useTranslation()
  const [copied, setCopied] = useState(false)
  if (!url) return null
  return (
    <div className="flex min-w-0 items-center gap-2">
      <code
        className="min-w-0 flex-1 rounded bg-muted px-2 py-1.5 font-mono text-xs break-all select-all"
        data-testid="owner-invitation-accept-url"
      >
        {url}
      </code>
      <Button
        type="button"
        size="sm"
        variant="outline"
        onClick={async () => {
          if (await copyToClipboard(url)) {
            setCopied(true)
            toast.success(t('admin.ownerInvitation.addressCopied', 'Address copied'))
          }
        }}
      >
        {copied ? (
          <Check className="me-2 size-4" aria-hidden="true" />
        ) : (
          <Copy className="me-2 size-4" aria-hidden="true" />
        )}
        {t('admin.ownerInvitation.copyAddress', 'Copy address')}
      </Button>
    </div>
  )
}

/**
 * What the administrator tells an invitee on an installation that cannot send
 * email: nothing was sent, so they hand over the address themselves.
 */
export function OwnerInvitationNotSentNotice({
  email,
  invitation,
}: {
  email?: string
  invitation?: AdminOwnerInvitation
}) {
  const { t } = useTranslation()
  return (
    <Alert data-testid="owner-invitation-not-sent">
      <MailX className="size-4" aria-hidden="true" />
      <AlertDescription className="space-y-2">
        <p className="font-medium">
          {t('admin.ownerInvitation.notSent', 'Not sent: this server cannot send email')}
        </p>
        <p className="text-muted-foreground">
          {email
            ? t(
                'admin.ownerInvitation.notSentHelpNamed',
                'Tell {email} yourself: ask them to sign in and open this address, where they accept or decline. Until then the organization has no owner and nobody can open it.',
                { email }
              )
            : t(
                'admin.ownerInvitation.notSentHelp',
                'Tell the person yourself: ask them to sign in and open this address, where they accept or decline. Until then the organization has no owner and nobody can open it.'
              )}
        </p>
        <OwnerInvitationAcceptAddress url={invitation?.accept_url} />
      </AlertDescription>
    </Alert>
  )
}

/** Shown after a create request invited an existing account to own the organization. */
export function OwnerInvitationSentNotice({
  email,
  invitation,
  emailDelivery,
}: {
  email: string
  invitation?: AdminOwnerInvitation
  /** False: the installation cannot send email, so nothing was sent. */
  emailDelivery?: boolean
}) {
  const { t } = useTranslation()
  if (emailDelivery === false) {
    return <OwnerInvitationNotSentNotice email={email} invitation={invitation} />
  }
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
  emailDelivery,
}: {
  tenantId: string
  invitation: AdminOwnerInvitation
  canManage: boolean
  changeInvitee?: React.ReactNode
  onChanged: () => void
  /** False: the installation cannot send email (no send, no sends left, the hand-over address). */
  emailDelivery?: boolean
}) {
  const { t } = useTranslation()
  const label = useStatusLabel()
  const [busy, setBusy] = useState(false)
  const [confirmCancel, setConfirmCancel] = useState(false)
  const open = invitation.status === 'pending' || invitation.status === 'expired'
  const noEmail = emailDelivery === false
  const resendReady =
    !noEmail &&
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
        {!noEmail && (
          <div>
            <dt className="text-xs">{t('admin.ownerInvitation.lastSent', 'Last sent')}</dt>
            <dd className="text-foreground">
              {invitation.last_sent_at ? (
                <RelativeTime date={invitation.last_sent_at} />
              ) : (
                t('admin.ownerInvitation.neverSent', 'Not sent')
              )}
            </dd>
          </div>
        )}
        <div>
          <dt className="text-xs">{t('admin.ownerInvitation.expires', 'Expires')}</dt>
          <dd className="text-foreground">
            <RelativeTime date={invitation.expires_at} />
          </dd>
        </div>
        {!noEmail && (
          <div>
            <dt className="text-xs">{t('admin.ownerInvitation.sends', 'Sends left')}</dt>
            <dd className="text-foreground">{invitation.resends_left}</dd>
          </div>
        )}
      </dl>
      {noEmail && open && (
        <OwnerInvitationNotSentNotice email={invitation.invitee_email} invitation={invitation} />
      )}
      <p className="text-muted-foreground">
        {noEmail && invitation.status === 'expired'
          ? t(
              'admin.ownerInvitation.expiredNoEmailHelp',
              'This invitation expired. To give the person seven more days, use Change invitee with the same email address.'
            )
          : open
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
          {open && !noEmail && (
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
        desc={
          noEmail
            ? t(
                'admin.ownerInvitation.cancelDescNoEmail',
                'No email is sent: tell the person yourself if they were expecting it. The organization stays without an owner until you invite someone else or create its first owner.'
              )
            : t(
                'admin.ownerInvitation.cancelDesc',
                'The person is told by email. The organization stays without an owner until you invite someone else or create its first owner.'
              )
        }
        confirmText={t('admin.ownerInvitation.cancel', 'Cancel invitation')}
        destructive
        handleConfirm={cancel}
      />
    </div>
  )
}
