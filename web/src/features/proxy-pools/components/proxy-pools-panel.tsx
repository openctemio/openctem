'use client'

import { Skeleton } from '@/components/ui/skeleton'
import { useTranslation } from '@/context/i18n-provider'
import { ErrorState, MetricStrip, PageStack } from '@/features/shared'
import { Permission, usePermissions } from '@/lib/permissions'

import { PROXY_HEALTH_REFRESH_MS, useProxyPools } from '../api/use-proxy-pools'
import { summarizePools } from '../lib/health-summary'
import { DefaultPoolSection } from './default-pool-section'
import { MorePoolsSection } from './more-pools-section'
import { ScannerAddressesCard } from './scanner-addresses-card'

/**
 * Settings, Scanning, Proxies. Writes need sensors:egress:write, delete
 * sensors:egress:delete. Health is re-read every 30 s while the page is
 * visible, so a quarantine or a recovery shows without a reload.
 */
export function ProxyPoolsPanel() {
  const { t } = useTranslation()
  const { can } = usePermissions()
  const canRead = can(Permission.SensorEgressRead)
  const canWrite = can(Permission.SensorEgressWrite)
  const canDelete = can(Permission.SensorEgressDelete)
  const { data, error, isLoading, mutate } = useProxyPools(canRead, PROXY_HEALTH_REFRESH_MS)
  const pools = data?.items ?? []

  if (error) {
    return (
      <ErrorState
        title={t('proxyPools.title', 'Proxies')}
        error={error}
        onRetry={() => void mutate()}
      />
    )
  }
  if (isLoading) return <Skeleton className="h-48 w-full" />

  const s = summarizePools(pools)
  return (
    <PageStack data-testid="proxy-pools-panel">
      {s.total > 0 && (
        <MetricStrip
          items={[
            {
              key: 'proxies',
              label: t('proxyPools.strip.proxies', 'Proxies in use'),
              value: s.total - s.disabled,
            },
            { key: 'healthy', label: t('proxyPools.state.healthy', 'Healthy'), value: s.healthy },
            {
              key: 'probation',
              label: t('proxyPools.state.probation', 'Probation'),
              value: s.probation,
              tone: 'warning',
            },
            {
              key: 'quarantined',
              label: t('proxyPools.state.quarantined', 'Quarantined'),
              value: s.quarantined,
              tone: 'danger',
            },
          ]}
        />
      )}
      <DefaultPoolSection pool={pools.find((p) => p.is_default)} canWrite={canWrite} />
      <MorePoolsSection
        pools={pools.filter((p) => !p.is_default)}
        canWrite={canWrite}
        canDelete={canDelete}
      />
      <ScannerAddressesCard enabled={canRead} />
    </PageStack>
  )
}
