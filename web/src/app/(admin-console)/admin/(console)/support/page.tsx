'use client'

import { Main } from '@/components/layout'
import { useTranslation } from '@/context/i18n-provider'
import { PageHeader } from '@/features/shared'
import { useAdmin } from '@/features/admin-console/components/admin-console-shell'
import { SupportAccessPanel } from '@/features/admin-console/components/support-access-panel'
import { adminCan } from '@/features/admin-console/types'

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
      <PageHeader
        title={t('admin.support.pageTitle', 'Support access')}
        description={t(
          'admin.support.pageDescription',
          'Organizations that granted you read-only access to help them, and your support sessions.'
        )}
      />
      <div className="mt-5">
        <SupportAccessPanel canSupport={adminCan(me.role, 'ops_admin')} />
      </div>
    </Main>
  )
}
