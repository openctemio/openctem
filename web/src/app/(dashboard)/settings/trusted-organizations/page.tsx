'use client'

import { Main } from '@/components/layout'
import { PageHeader, PageStack } from '@/features/shared'
import { TrustedOrganizations } from '@/features/organization/components/trusted-organizations'
import { usePermissions } from '@/lib/permissions'
import { useTranslation } from '@/context/i18n-provider'

/**
 * Settings › Trusted organizations (api RFC-058): partner organizations whose
 * people sign in here with their own company's SSO, and organizations that
 * trust this one. Owners change trusts; admins read them.
 */
export default function TrustedOrganizationsPage() {
  const { t } = useTranslation()
  const { isOwner, isAtLeast, isLoading } = usePermissions()
  return (
    <Main>
      <PageStack>
        <PageHeader
          title={t('settings.trust.title', 'Trusted organizations')}
          description={t(
            'settings.trust.description',
            "Partner organizations whose people sign in here with their own company's SSO. A trust applies once both owners agree."
          )}
        />
        {!isLoading && <TrustedOrganizations canRead={isAtLeast('admin')} isOwner={isOwner()} />}
      </PageStack>
    </Main>
  )
}
