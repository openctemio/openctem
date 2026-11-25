'use client'

import { useState, useTransition } from 'react'
import { LogOut } from 'lucide-react'

import { Button } from '@/components/ui/button'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { useTranslation } from '@/context/i18n-provider'
import { localLogoutAction } from '@/features/auth/actions/local-auth-actions'
import { useAuthStore } from '@/stores/auth-store'

/**
 * "Sign out?" for the account space: confirming ends the session on the API
 * and clears the cookies. Shared by the header button and the phone menu,
 * which opens it after the menu has closed.
 */
export function AccountSignOutConfirm({
  open,
  onOpenChange,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
}) {
  const { t } = useTranslation()
  const [pending, startTransition] = useTransition()
  const clearAuth = useAuthStore((s) => s.clearAuth)

  const signOut = () => {
    onOpenChange(false)
    try {
      sessionStorage.removeItem('app_user')
    } catch {
      // Storage may be blocked; the cookies are what matter.
    }
    clearAuth()
    startTransition(async () => {
      await localLogoutAction('/login')
    })
  }

  return (
    <ConfirmDialog
      open={open}
      onOpenChange={onOpenChange}
      title={t('auth.welcome.signOutTitle', 'Sign out?')}
      desc={t('auth.welcome.signOutDesc', 'You will need to sign in again to open your account.')}
      confirmText={
        pending
          ? t('auth.welcome.signingOut', 'Signing out')
          : t('auth.welcome.signOut', 'Sign out')
      }
      cancelBtnText={t('common.cancel', 'Cancel')}
      handleConfirm={signOut}
      className="sm:max-w-sm"
    />
  )
}

/** Sign out of the account space: the header button and its confirmation. */
export function AccountSignOut({ className }: { className?: string }) {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)

  return (
    <>
      <Button variant="outline" className={className} onClick={() => setOpen(true)}>
        <LogOut aria-hidden />
        {t('auth.welcome.signOut', 'Sign out')}
      </Button>
      <AccountSignOutConfirm open={open} onOpenChange={setOpen} />
    </>
  )
}
