'use client'

import { LogOut } from 'lucide-react'

import { SignOutButton } from '@/components/sign-out-dialog'
import { buttonVariants } from '@/components/ui/button'
import { useTranslation } from '@/context/i18n-provider'

export function OnboardingLogout() {
  const { t } = useTranslation()
  return (
    <SignOutButton className={buttonVariants({ variant: 'ghost' })} redirectTo="/login">
      <LogOut aria-hidden className="size-4" />
      <span>{t('auth.welcome.signOut', 'Sign out')}</span>
    </SignOutButton>
  )
}
