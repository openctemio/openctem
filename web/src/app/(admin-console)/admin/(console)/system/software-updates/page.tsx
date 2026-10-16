'use client'

import { Main } from '@/components/layout'
import { Skeleton } from '@/components/ui/skeleton'
import { useTranslation } from '@/context/i18n-provider'
import { ErrorState, PageHeader } from '@/features/shared'
import { useAdmin } from '@/features/admin-console/components/admin-console-shell'
import { useVersionCheck } from '@/features/admin-console/api/use-version-check'
import { SoftwareUpdatesPanel } from '@/features/admin-console/components/software-updates-panel'
import { adminCan } from '@/features/admin-console/types'

/**
 * System -> Software updates: newer releases and the security advisories
 * that affect this instance, from the signed release feed (RFC-105). Any
 * administrator sees it; super admins import the feed file offline.
 */
export default function SoftwareUpdatesPage() {
  const { t } = useTranslation()
  const me = useAdmin()
  const { data, error, isLoading, mutate } = useVersionCheck()

  return (
    <Main>
      <PageHeader
        title={t('admin.nav.softwareUpdates', 'Software updates')}
        description={t(
          'admin.versionCheck.pageDescription',
          'Newer releases and security advisories for this instance, from the signed release feed.'
        )}
      />
      <div className="mt-5">
        {error ? (
          <ErrorState
            title={t('admin.versionCheck.errorSubject', 'the release information')}
            error={error}
            onRetry={() => void mutate()}
          />
        ) : isLoading || !data ? (
          <Skeleton className="h-72 w-full" />
        ) : (
          <SoftwareUpdatesPanel
            status={data}
            canImport={adminCan(me.role, 'super_admin')}
            onChanged={() => void mutate()}
          />
        )}
      </div>
    </Main>
  )
}
