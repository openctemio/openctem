'use client'

import Link from '@/components/link'
import { EntryActions, EntryBackLink, EntryCard, EntryHeader } from '@/components/entry'
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
    <EntryCard>
      <EntryHeader
        title={t('auth.notSetUp.title', "Your organization isn't set up yet")}
        description={t(
          'auth.notSetUp.body',
          'This sign-in did not lead to an account on this installation, and accounts are not created automatically here.'
        )}
      />
      <ul className="text-body text-muted-foreground flex list-disc flex-col gap-1.5 ps-5">
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
      <EntryActions>
        {providers?.request_access && (
          <Button variant="signal" asChild>
            <Link href="/request-access">{t('auth.requestAccess.cta', 'Request access')}</Link>
          </Button>
        )}
        <EntryBackLink />
      </EntryActions>
    </EntryCard>
  )
}
