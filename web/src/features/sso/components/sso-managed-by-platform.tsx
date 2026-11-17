'use client'

import Link from '@/components/link'
import { ShieldCheck } from 'lucide-react'

import { Main } from '@/components/layout'
import { Button } from '@/components/ui/button'
import { EmptyState, PageHeader, PageStack, SettingsSection } from '@/features/shared'
import { useTranslation } from '@/context/i18n-provider'

/** One wording for every place that explains where SSO is configured. */
export const SSO_MANAGED_TITLE = 'SSO is configured by your platform administrator'
const ssoManagedText = (what: string) =>
  `${what} is set up for your organization in the platform administration console. To add or change it, contact your platform administrator.`

interface SsoManagedByPlatformProps {
  /** Page title, e.g. "SAML single sign-on". */
  title: string
  /** What the page used to configure, in one sentence. */
  what: string
}

/**
 * Shown on the tenant settings pages whose configuration moved to the
 * platform admin console (RFC-022): SSO and verified domains are set per
 * organization by a platform administrator. These routes used to redirect
 * into the admin console, which put a tenant owner on a sign-in page for an
 * account they do not have.
 */
export function SsoManagedByPlatform({ title, what }: SsoManagedByPlatformProps) {
  const { t } = useTranslation()
  return (
    <Main>
      <PageStack>
        <PageHeader title={title} />
        <div>
          <EmptyState
            icon={ShieldCheck}
            title={t('org.sso.managedTitle', SSO_MANAGED_TITLE)}
            description={t('org.sso.managedText', ssoManagedText('{what}'), { what })}
            action={
              <Button asChild variant="outline" size="sm">
                <Link href="/settings/sign-in">
                  {t('org.sso.authLink', 'Authentication settings')}
                </Link>
              </Button>
            }
          />
        </div>
      </PageStack>
    </Main>
  )
}

/**
 * The same explanation as a section of Settings › Sign-in: that page holds
 * the organization's own sign-in rules, and this says where SSO (SAML/OIDC
 * providers, verified domains, enforcement) is set instead.
 */
export function SsoManagedNotice() {
  const { t } = useTranslation()
  return (
    <SettingsSection
      framed
      id="single-sign-on"
      title={t('org.sso.title', 'Single sign-on')}
      description={
        <>
          {t('org.sso.managedTitle', SSO_MANAGED_TITLE)}.{' '}
          {t(
            'org.sso.noticeText',
            'Single sign-on (SAML or OIDC), with verified domains, is set up for your organization in the platform administration console. To add or change it, contact your platform administrator.'
          )}
        </>
      }
    />
  )
}
