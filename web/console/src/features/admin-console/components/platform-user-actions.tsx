'use client'

import { useState } from 'react'
import {
  Ban,
  Copy,
  KeyRound,
  LogOut,
  MailCheck,
  ShieldCheck,
  ShieldOff,
  Unlock,
  UserCheck,
} from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { DangerZone, DangerZoneItem } from '@/features/shared'
import { useTranslation } from '@/context/i18n-provider'
import { OneTimeLinkDialog } from '@/components/one-time-link-dialog'
import { issuePlatformUserResetLink, runPlatformUserAction } from '../api/use-platform-users'
import { AdminConfirmDialog } from './admin-confirm-dialog'
import type { PlatformUserAction, PlatformUserDetail } from '../types'

/**
 * Support actions on one account (ops admin and up). Only the actions that
 * apply to the account's state are offered; each asks for a reason, which the
 * API keeps in the admin audit log. Platform administrator and erased
 * accounts get none (the API refuses them too).
 */
interface ActionSpec {
  action: PlatformUserAction
  icon: typeof LogOut
  labelKey: string
  label: string
  whatKey: string
  what: string
  doneKey: string
  done: string
  /** An example reason for this action (the reason field's placeholder). */
  reasonKey: string
  reason: string
  destructive?: boolean
  /** Super admin only (the API refuses ops_admin). */
  superOnly?: boolean
  available: (u: PlatformUserDetail) => boolean
}

// On a server that cannot send email the email actions would only fail, and
// the copied link / mark verified take their place.
const emailOn = (u: PlatformUserDetail) => u.email_delivery !== false
const emailOff = (u: PlatformUserDetail) => u.email_delivery === false

const ACTIONS: ActionSpec[] = [
  {
    action: 'revoke-sessions',
    icon: LogOut,
    labelKey: 'admin.users.action.revoke',
    label: 'Sign out everywhere',
    whatKey: 'admin.users.action.revokeWhat',
    what: 'Ends every session of {email} in every organization and on every device. They sign in again; nothing else changes.',
    doneKey: 'admin.users.action.revokeDone',
    done: 'Signed out everywhere.',
    reasonKey: 'admin.users.action.revokeReason',
    reason: 'Phone stolen, the user called the help desk, ticket 2231',
    destructive: true,
    available: (u) => u.sessions.length > 0,
  },
  {
    action: 'unlock',
    icon: Unlock,
    labelKey: 'admin.users.action.unlock',
    label: 'Unlock',
    whatKey: 'admin.users.action.unlockWhat',
    what: 'Clears the lockout after failed sign-ins for {email}, so they can try again now.',
    doneKey: 'admin.users.action.unlockDone',
    done: 'Account unlocked.',
    reasonKey: 'admin.users.action.unlockReason',
    reason: 'Locked out after a password manager mix-up, ticket 2231',
    available: (u) => u.locked || u.failed_logins > 0,
  },
  {
    action: 'password-reset',
    icon: KeyRound,
    labelKey: 'admin.users.action.reset',
    label: 'Send password reset',
    whatKey: 'admin.users.action.resetWhat',
    what: 'Emails {email} a password reset link, the same as "Forgot password". You never see the link.',
    doneKey: 'admin.users.action.resetDone',
    done: 'Password reset link emailed.',
    reasonKey: 'admin.users.action.resetReason',
    reason: 'Forgot the password and asked by phone, ticket 2231',
    available: (u) => u.auth_provider === 'local' && emailOn(u),
  },
  {
    action: 'verification-emails',
    icon: MailCheck,
    labelKey: 'admin.users.action.verify',
    label: 'Resend verification',
    whatKey: 'admin.users.action.verifyWhat',
    what: 'Emails {email} a new verification link; the previous one stops working.',
    doneKey: 'admin.users.action.verifyDone',
    done: 'Verification email sent.',
    reasonKey: 'admin.users.action.verifyReason',
    reason: 'The first email went to spam, ticket 2231',
    available: (u) => !u.email_verified && emailOn(u),
  },
  {
    action: 'password-reset',
    icon: Copy,
    labelKey: 'admin.users.action.resetLink',
    label: 'Copy reset link',
    whatKey: 'admin.users.action.resetLinkWhat',
    what: 'This server cannot send email. Creates a one-hour password reset link for {email} and shows it once, for you to hand over over a channel you trust. Any earlier reset link stops working. They still need their second factor to sign in.',
    doneKey: 'admin.users.action.resetLinkDone',
    done: 'Reset link created.',
    reasonKey: 'admin.users.action.resetLinkReason',
    reason: 'No email on this server; link handed over in person, ticket 2231',
    superOnly: true,
    available: (u) => u.auth_provider === 'local' && emailOff(u),
  },
  {
    action: 'mark-verified',
    icon: UserCheck,
    labelKey: 'admin.users.action.markVerified',
    label: 'Mark email verified',
    whatKey: 'admin.users.action.markVerifiedWhat',
    what: 'This server cannot send the verification link. Marks the email address of {email} as verified; only do this once you have confirmed the address is theirs.',
    doneKey: 'admin.users.action.markVerifiedDone',
    done: 'Email marked verified.',
    reasonKey: 'admin.users.action.markVerifiedReason',
    reason: 'Address confirmed by their manager in writing, ticket 2231',
    superOnly: true,
    available: (u) => u.auth_provider === 'local' && !u.email_verified && emailOff(u),
  },
  {
    action: 'mfa/reset',
    icon: ShieldOff,
    labelKey: 'admin.users.action.mfaReset',
    label: 'Reset two-factor',
    whatKey: 'admin.users.action.mfaResetWhat',
    what: 'Turns off two-factor authentication for {email} and ends every session. Use it for someone who lost their device and recovery codes and has no organization administrator above them. Another super admin must approve first.',
    doneKey: 'admin.users.action.mfaResetDone',
    done: 'Two-factor authentication reset.',
    reasonKey: 'admin.users.action.mfaResetReason',
    reason: 'Lost their phone and recovery codes, identity checked by video call, ticket 2231',
    destructive: true,
    superOnly: true,
    available: (u) => u.auth_provider === 'local' && u.mfa_enabled,
  },
  {
    action: 'block',
    icon: Ban,
    labelKey: 'admin.users.action.block',
    label: 'Block account',
    whatKey: 'admin.users.action.blockWhat',
    what: 'Blocks {email} in every organization: they cannot sign in, their sessions end now, and their API keys and MCP tokens stop working. Nothing they made is removed.',
    doneKey: 'admin.users.action.blockDone',
    done: 'Account blocked.',
    reasonKey: 'admin.users.action.blockReason',
    reason: 'Account used for abuse, report 2231',
    destructive: true,
    available: (u) => !u.blocked && u.status === 'active',
  },
  {
    action: 'unblock',
    icon: ShieldCheck,
    labelKey: 'admin.users.action.unblock',
    label: 'Unblock account',
    whatKey: 'admin.users.action.unblockWhat',
    what: 'Lets {email} sign in again. Their old sessions stay ended.',
    doneKey: 'admin.users.action.unblockDone',
    done: 'Account unblocked.',
    reasonKey: 'admin.users.action.unblockReason',
    reason: 'Report 2231 closed: the account was not involved',
    available: (u) => u.blocked,
  },
]

/**
 * Why an account offers none of these actions (a platform administrator, an
 * erased account), for the line under the page title; undefined otherwise.
 */
export function platformUserUnavailableNote(
  t: ReturnType<typeof useTranslation>['t'],
  user: Pick<PlatformUserDetail, 'is_platform_admin' | 'erased'>
): string | undefined {
  if (user.is_platform_admin)
    return t(
      'admin.users.blockedAdmin',
      'This is a platform administrator account; manage it in Security > Administrators.'
    )
  if (user.erased) return t('admin.users.blockedErased', 'This account was erased.')
  return undefined
}

export function PlatformUserActions({
  user,
  onDone,
  isSuperAdmin = false,
  part = 'routine',
}: {
  user: PlatformUserDetail
  onDone: () => void
  /** The signed-in administrator is a super admin (offers the recovery actions). */
  isSuperAdmin?: boolean
  /**
   * routine: the everyday actions, under the account's name; danger: the ones
   * that cut the person off (sign out everywhere, reset two-factor, block),
   * in the shared danger zone at the end of the page.
   */
  part?: 'routine' | 'danger'
}) {
  const { t } = useTranslation()
  const [open, setOpen] = useState<ActionSpec | null>(null)
  const [resetLink, setResetLink] = useState<{ link: string; expiresAt: string } | null>(null)
  const unavailable = user.is_platform_admin || user.erased
  const offered = ACTIONS.filter(
    (a) =>
      (!a.superOnly || isSuperAdmin) && a.available(user) && !!a.destructive === (part === 'danger')
  )

  if (part === 'danger') {
    if (unavailable || offered.length === 0) return null
    return (
      <>
        <DangerZone>
          {offered.map((a) => (
            <DangerZoneItem
              key={a.action}
              title={t(a.labelKey, a.label)}
              description={t(a.whatKey, a.what, { email: user.email })}
              action={
                <Button size="sm" variant="destructive" onClick={() => setOpen(a)}>
                  <a.icon className="me-2 size-4" aria-hidden />
                  {t(a.labelKey, a.label)}
                </Button>
              }
            />
          ))}
        </DangerZone>
        {open && (
          <AdminConfirmDialog
            open
            onOpenChange={(next) => !next && setOpen(null)}
            title={t(open.labelKey, open.label)}
            description={<p>{t(open.whatKey, open.what, { email: user.email })}</p>}
            confirmLabel={t(open.labelKey, open.label)}
            reasonPlaceholder={t(open.reasonKey, open.reason)}
            destructive
            onConfirm={async ({ reason }) => {
              await runPlatformUserAction(user.id, open.action, reason)
              toast.success(t(open.doneKey, open.done))
              onDone()
            }}
          />
        )}
      </>
    )
  }

  return (
    <>
      {/* An account these actions cannot change (a platform administrator, an
          erased account) gets no greyed-out buttons: the page says why under
          its title (platformUserUnavailableNote). */}
      {offered.length > 0 && !unavailable && (
        <div className="flex flex-wrap gap-2">
          {offered.map((a) => (
            <Button key={a.action} size="sm" variant="outline" onClick={() => setOpen(a)}>
              <a.icon className="me-2 size-4" aria-hidden />
              {t(a.labelKey, a.label)}
            </Button>
          ))}
        </div>
      )}
      {user.blocked && !unavailable && (
        <p className="text-sm text-muted-foreground">
          {user.blocked_reason
            ? t('admin.users.blockedReason', 'Blocked: {reason}', { reason: user.blocked_reason })
            : t('admin.users.blockedNoReason', 'This account is blocked.')}
        </p>
      )}
      {open && (
        <AdminConfirmDialog
          open
          onOpenChange={(next) => !next && setOpen(null)}
          title={t(open.labelKey, open.label)}
          description={<p>{t(open.whatKey, open.what, { email: user.email })}</p>}
          confirmLabel={t(open.labelKey, open.label)}
          reasonPlaceholder={t(open.reasonKey, open.reason)}
          destructive={open.destructive}
          onConfirm={async ({ reason }) => {
            if (open.labelKey === 'admin.users.action.resetLink') {
              // The link is a bearer secret: it goes straight into the
              // dialog below and nowhere else.
              const res = await issuePlatformUserResetLink(user.id, reason)
              setResetLink({ link: res.link, expiresAt: res.expires_at })
            } else {
              await runPlatformUserAction(user.id, open.action, reason)
            }
            toast.success(t(open.doneKey, open.done))
            onDone()
          }}
        />
      )}
      <OneTimeLinkDialog
        open={!!resetLink}
        onOpenChange={(next) => {
          if (!next) setResetLink(null)
        }}
        title={t('admin.users.action.resetLink', 'Copy reset link')}
        description={t(
          'admin.users.action.resetLinkFor',
          'Password reset link for {email}. It works once.',
          { email: user.email }
        )}
        link={resetLink?.link ?? ''}
        expiresAt={resetLink?.expiresAt}
      />
    </>
  )
}
