'use client'

import { Main } from '@/components/layout'
import { useTranslation } from '@/context/i18n-provider'
import { DomainSignupPolicies } from '@/features/organization/components/domain-signup-policies'
import { PageHeader, PageStack } from '@/features/shared'
import { usePermissions } from '@/lib/permissions'

/**
 * Settings › Domains (api RFC-104): what the organization's verified single
 * sign-on domains do to accounts on them. Owners change it; admins read it.
 */
export default function DomainsSettingsPage() {
  const { t } = useTranslation()
  const { isOwner, isAtLeast, isLoading } = usePermissions()
  return (
    <Main>
      <PageStack>
        <PageHeader title={t('settings.domains.title')} description={t('settings.domains.desc')} />
        {!isLoading && <DomainSignupPolicies canRead={isAtLeast('admin')} isOwner={isOwner()} />}
      </PageStack>
    </Main>
  )
}
