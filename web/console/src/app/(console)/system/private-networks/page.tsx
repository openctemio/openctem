'use client'

import { Main } from '@/components/layout'
import { Skeleton } from '@/components/ui/skeleton'
import { useTranslation } from '@/context/i18n-provider'
import { ErrorState, PageHeader, PageStack } from '@/features/shared'
import { useAdmin } from '@console/features/admin-console/components/admin-console-shell'
import { usePrivateDestinations } from '@console/features/admin-console/api/use-platform-settings'
import {
  NETWORK_PERMISSION,
  PrivateDestinationsPanel,
} from '@console/features/admin-console/components/private-destinations-panel'
import { adminHas } from '@console/features/admin-console/types'

/**
 * System -> Private networks: the private ranges the platform's outbound
 * requests may reach. Any administrator sees them; a platform owner changes
 * them and tests a destination.
 */
export default function PrivateNetworksSettingsPage() {
  const { t } = useTranslation()
  const me = useAdmin()
  const { data, error, isLoading, mutate } = usePrivateDestinations()

  return (
    <Main>
      <PageStack>
        <PageHeader
          title={t('admin.privateNetworks.pageTitle', 'Private networks')}
          description={t(
            'admin.privateNetworks.pageDescription',
            'Private addresses the platform may connect to on your network.'
          )}
        />
        {error ? (
          <ErrorState
            title={t('admin.privateNetworks.errorSubject', 'the private network setting')}
            error={error}
            onRetry={() => void mutate()}
          />
        ) : isLoading || !data ? (
          <Skeleton className="h-64 w-full" />
        ) : (
          <PrivateDestinationsPanel
            settings={data}
            canEdit={adminHas(me, NETWORK_PERMISSION)}
            onSaved={() => void mutate()}
          />
        )}
      </PageStack>
    </Main>
  )
}
