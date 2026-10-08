'use client'

import { useState } from 'react'
import { KeyRound, LogOut, MailCheck, Unlock } from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { useTranslation } from '@/context/i18n-provider'
import { runPlatformUserAction } from '../api/use-platform-users'
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
  destructive?: boolean
  available: (u: PlatformUserDetail) => boolean
}

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
    available: (u) => u.auth_provider === 'local',
  },
  {
    action: 'resend-verification',
    icon: MailCheck,
    labelKey: 'admin.users.action.verify',
    label: 'Resend verification',
    whatKey: 'admin.users.action.verifyWhat',
    what: 'Emails {email} a new verification link; the previous one stops working.',
    doneKey: 'admin.users.action.verifyDone',
    done: 'Verification email sent.',
    available: (u) => !u.email_verified,
  },
]

export function PlatformUserActions({
  user,
  onDone,
}: {
  user: PlatformUserDetail
  onDone: () => void
}) {
  const { t } = useTranslation()
  const [open, setOpen] = useState<ActionSpec | null>(null)
  const blocked = user.is_platform_admin || user.erased

  return (
    <>
      <div className="flex flex-wrap gap-2">
        {ACTIONS.filter((a) => a.available(user)).map((a) => (
          <Button
            key={a.action}
            size="sm"
            variant={a.destructive ? 'destructive' : 'outline'}
            disabled={blocked}
            onClick={() => setOpen(a)}
          >
            <a.icon className="me-2 size-4" />
            {t(a.labelKey, a.label)}
          </Button>
        ))}
      </div>
      {blocked && (
        <p className="text-sm text-muted-foreground">
          {user.is_platform_admin
            ? t(
                'admin.users.blockedAdmin',
                'This is a platform administrator account; manage it in Security > Administrators.'
              )
            : t('admin.users.blockedErased', 'This account was erased.')}
        </p>
      )}
      {open && (
        <AdminConfirmDialog
          open
          onOpenChange={(next) => !next && setOpen(null)}
          title={t(open.labelKey, open.label)}
          description={<p>{t(open.whatKey, open.what, { email: user.email })}</p>}
          confirmLabel={t(open.labelKey, open.label)}
          destructive={open.destructive}
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
