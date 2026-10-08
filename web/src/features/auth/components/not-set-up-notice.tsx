'use client'

import Link from 'next/link'
import { Building2 } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { useTranslation } from '@/context/i18n-provider'

/**
 * The one page every refused sign-up lands on (email sign-up, Google,
 * Microsoft or GitHub sign-in), whatever the reason. It never names an
 * organization or says whether the email has an account, so it reveals
 * nothing to someone probing addresses.
 */
export function NotSetUpNotice() {
  const { t } = useTranslation()
  return (
    <div className="mx-auto flex w-full max-w-md flex-col items-center gap-4 text-center">
      <div className="flex size-12 items-center justify-center rounded-full bg-muted">
        <Building2 className="size-6 text-muted-foreground" aria-hidden />
      </div>
      <h1 className="text-xl font-semibold">
        {t('auth.notSetUp.title', "Your organization isn't set up yet")}
      </h1>
      <p className="text-sm text-muted-foreground">
        {t(
          'auth.notSetUp.body',
          'Ask your administrator to invite you. If you received an invitation email, open its link to join.'
        )}
      </p>
      <Button asChild variant="outline">
        <Link href="/login">{t('auth.notSetUp.backToSignIn', 'Back to sign in')}</Link>
      </Button>
    </div>
  )
}
