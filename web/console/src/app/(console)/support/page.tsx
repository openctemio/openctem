'use client'

import { Main } from '@/components/layout'
import { useTranslation } from '@/context/i18n-provider'
import { PageHeader, PageStack } from '@/features/shared'
import { useAdmin } from '@console/features/admin-console/components/admin-console-shell'
import { SupportAccessPanel } from '@console/features/admin-console/components/support-access-panel'
import { adminHas } from '@console/features/admin-console/types'

/**
 * Customers › Support access (api RFC-063): organizations whose owner let the
 * signed-in administrator read chosen data for a few hours, and the read-only
 * support session opened from one grant.
 */
export default function SupportAccessPage() {
  const { t } = useTranslation()
  const me = useAdmin()
  return (
    <Main>
      <PageStack>
        <PageHeader
          title={t('admin.support.pageTitle', 'Support access')}
          description={t(
            'admin.support.pageDescription',
            'Organizations that granted you read-only access to help them, and your support sessions.'
          )}
        />
        <SupportAccessPanel canSupport={adminHas(me, 'platform.support.access')} />
      </PageStack>
    </Main>
  )
}
