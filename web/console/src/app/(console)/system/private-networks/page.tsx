'use client'

import { useTranslation } from '@/context/i18n-provider'
import { SettingsPage } from '@/features/shared'
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
 * them and tests a destination. The shared settings frame: flat sections
 * divided by hairlines in the reading column.
 */
export default function PrivateNetworksSettingsPage() {
  const { t } = useTranslation()
  const me = useAdmin()
  const { data, error, isLoading, mutate } = usePrivateDestinations()

  return (
    <SettingsPage
      title={t('admin.privateNetworks.pageTitle', 'Private networks')}
      description={t(
        'admin.privateNetworks.pageDescription',
        'Private addresses the platform may connect to on your network.'
      )}
      state={error ? 'error' : isLoading || !data ? 'loading' : 'ready'}
      error={error}
      onRetry={() => void mutate()}
    >
      {data && (
        <PrivateDestinationsPanel
          settings={data}
          canEdit={adminHas(me, NETWORK_PERMISSION)}
          onSaved={() => void mutate()}
        />
      )}
    </SettingsPage>
  )
}
