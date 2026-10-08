'use client'

import { Main } from '@/components/layout'
import { PageHeader } from '@/features/shared'
import { useAdmin } from '@/features/admin-console/components/admin-console-shell'
import { AccessRequestsPanel } from '@/features/admin-console/components/access-requests-panel'
import { adminCan } from '@/features/admin-console/types'

/**
 * Organizations -> Access requests: people who asked for an organization while
 * sign-up is closed. Approving creates the organization with the requester as
 * its owner.
 */
export default function AccessRequestsPage() {
  const me = useAdmin()
  return (
    <Main>
      <PageHeader
        title="Access requests"
        description="People who asked for an organization while sign-up is closed."
      />
      <div className="mt-5">
        <AccessRequestsPanel canDecide={adminCan(me.role, 'ops_admin')} />
      </div>
    </Main>
  )
}
