'use client'

import Link from '@/components/link'
import { Building2 } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { useTranslation } from '@/context/i18n-provider'
import { useAuthProviders } from '../api/use-auth-providers'

/**
 * The one page every refused sign-up lands on (email sign-up, Google,
 * Microsoft or GitHub sign-in), whatever the reason. It never names an
 * organization or says whether the email has an account, so it reveals
 * nothing to someone probing addresses.
 */
export function NotSetUpNotice() {
  const { t } = useTranslation()
  const { data: providers } = useAuthProviders()
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
          'This sign-in did not lead to an account on this installation, and accounts are not created automatically here.'
        )}
      </p>
      <ul className="w-full list-disc space-y-1.5 ps-5 text-start text-sm text-muted-foreground">
        <li>
          {t(
            'auth.notSetUp.stepOtherMethod',
            'Try another way to sign in, such as your email and password or a different provider.'
          )}
        </li>
        <li>
          {t(
            'auth.notSetUp.stepAskAdmin',
            'Ask your administrator to invite the email address you signed in with.'
          )}
        </li>
        <li>
          {t(
            'auth.notSetUp.stepInvitation',
            'If you received an invitation email, open its link to join.'
          )}
        </li>
      </ul>
      <div className="flex flex-wrap justify-center gap-2">
        {providers?.request_access && (
          <Button asChild>
            <Link href="/request-access">{t('auth.requestAccess.cta', 'Request access')}</Link>
          </Button>
        )}
        <Button asChild variant="outline">
          <Link href="/login">{t('auth.notSetUp.backToSignIn', 'Back to sign in')}</Link>
        </Button>
      </div>
    </div>
  )
}
