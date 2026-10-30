'use client'

import { Skeleton } from '@/components/ui/skeleton'
import { useTranslation } from '@/context/i18n-provider'
import { ErrorState, PageStack } from '@/features/shared'
import { Permission, usePermissions } from '@/lib/permissions'

import { useProxyPools } from '../api/use-proxy-pools'
import { DefaultPoolCard } from './default-pool-card'
import { MorePoolsSection } from './more-pools-section'

/** Settings, Scanning, Proxies. Writes need sensors:egress:write, delete sensors:egress:delete. */
export function ProxyPoolsPanel() {
  const { t } = useTranslation()
  const { can } = usePermissions()
  const canRead = can(Permission.SensorEgressRead)
  const canWrite = can(Permission.SensorEgressWrite)
  const canDelete = can(Permission.SensorEgressDelete)
  const { data, error, isLoading, mutate } = useProxyPools(canRead)
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

  return (
    <PageStack data-testid="proxy-pools-panel">
      <DefaultPoolCard pool={pools.find((p) => p.is_default)} canWrite={canWrite} />
      <MorePoolsSection
        pools={pools.filter((p) => !p.is_default)}
        canWrite={canWrite}
        canDelete={canDelete}
      />
    </PageStack>
  )
}
