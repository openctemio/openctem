'use client'

import { useTranslation } from '@/context/i18n-provider'
import { Main } from '@/components/layout'
import { PageHeader, PageStack } from '@/features/shared'
import { useAdmin } from '@console/features/admin-console/components/admin-console-shell'
import { AccessRequestsPanel } from '@console/features/admin-console/components/access-requests-panel'
import { adminHas } from '@console/features/admin-console/types'

/**
 * Requests -> Access requests: people who asked for an organization while
 * sign-up is closed. Approving creates the organization with the requester as
 * its owner. The overview's attention queue links here while any wait.
 */
export default function AccessRequestsPage() {
  const { t } = useTranslation()

  const me = useAdmin()
  return (
    <Main>
      <PageStack>
        <PageHeader
          title={t('admin.requestsPage.accessRequests', 'Access requests')}
          description={t(
            'admin.requestsPage.peopleWhoAskedForAn',
            'People who asked for an organization while sign-up is closed.'
          )}
        />
        <AccessRequestsPanel canDecide={adminHas(me, 'platform.tenants.create')} />
      </PageStack>
    </Main>
  )
}
