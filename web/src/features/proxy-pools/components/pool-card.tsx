'use client'

import type { ReactNode } from 'react'
import { Pencil, Trash2 } from 'lucide-react'

import { Badge } from '@/components/ui/badge'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { useTranslation } from '@/context/i18n-provider'
import { GatedButton } from '@/features/shared'

import { summarizeEndpoints } from '../lib/health-summary'
import type { ProxyPool } from '../types'
import { EndpointTable } from './endpoint-table'
import { TestPoolButton } from './test-pool-button'

interface PoolCardProps {
  pool: ProxyPool
  canWrite: boolean
  /** Shown beside the title when the pool carries no traffic (Off, Disabled). */
  stateBadge?: string
  onEdit: () => void
  /** Omitted for the organization default, which is turned off, not deleted. */
  onDelete?: () => void
  /** Delete is allowed (permission and no sensor on the pool). */
  canDelete?: boolean
  /** Why Delete is not allowed. */
  deleteReason?: string
  /** Extra lines under the summary (the default pool's impact list). */
  children?: ReactNode
}

/**
 * One pool: its name, a health summary, how it routes, who uses it, the
 * actions, and its proxies. The organization default and every other pool
 * use this same card, edited through the same dialog.
 */
export function PoolCard({
  pool,
  canWrite,
  stateBadge,
  onEdit,
  onDelete,
  canDelete = false,
  deleteReason,
  children,
}: PoolCardProps) {
  const { t } = useTranslation()
  const s = summarizeEndpoints(pool.endpoints)
  const noWrite = t(
    'proxyPools.noWrite',
    'You need the sensors:egress:write permission to change pools'
  )

  const health = [
    s.total === 1
      ? t('proxyPools.summary.proxies.one', '{count} proxy', { count: s.total })
      : t('proxyPools.summary.proxies.other', '{count} proxies', { count: s.total }),
    s.healthy > 0 && t('proxyPools.summary.healthy', '{count} healthy', { count: s.healthy }),
    s.probation > 0 &&
      t('proxyPools.summary.probation', '{count} on probation', { count: s.probation }),
    s.quarantined > 0 &&
      t('proxyPools.summary.quarantined', '{count} quarantined', { count: s.quarantined }),
    s.disabled > 0 && t('proxyPools.summary.disabled', '{count} disabled', { count: s.disabled }),
  ].filter(Boolean)

  const strategy =
    pool.strategy === 'priority'
      ? t('proxyPools.summary.priority', 'Priority order')
      : t('proxyPools.summary.sticky', 'Sticky by target')

  return (
    <Card data-testid={pool.is_default ? 'default-pool-card' : 'pool-row'}>
      <CardHeader className="space-y-1">
        <div className="flex flex-wrap items-start justify-between gap-x-4 gap-y-2">
          <div className="min-w-0 flex-[1_1_16rem] space-y-1">
            <CardTitle className="flex flex-wrap items-center gap-2 text-base">
              <span className="break-words">{pool.name}</span>
              {stateBadge && (
                <Badge variant="secondary" className="font-normal">
                  {stateBadge}
                </Badge>
              )}
            </CardTitle>
            <p
              className="flex flex-wrap gap-x-4 gap-y-0.5 text-sm text-muted-foreground"
              data-testid="pool-summary"
            >
              <span className="tabular-nums" data-testid="pool-health-summary">
                {health.join(', ')}
              </span>
              <span>{strategy}</span>
              {!pool.is_default && (
                <span>
                  {pool.assigned_sensors === 1
                    ? t('proxyPools.assignedSensors.one', '{count} sensor assigned', {
                        count: pool.assigned_sensors,
                      })
                    : t('proxyPools.assignedSensors.other', '{count} sensors assigned', {
                        count: pool.assigned_sensors,
                      })}
                </span>
              )}
            </p>
            {pool.description && (
              <p className="text-sm break-words text-muted-foreground text-pretty">
                {pool.description}
              </p>
            )}
          </div>
          <div className="flex shrink-0 flex-wrap items-center gap-2">
            <TestPoolButton pool={pool} canWrite={canWrite} />
            <GatedButton
              allowed={canWrite}
              reason={noWrite}
              variant="outline"
              size="sm"
              onClick={onEdit}
              aria-label={t('proxyPools.editNamed', 'Edit {name}', { name: pool.name })}
            >
              <Pencil className="size-4" aria-hidden />
              {t('proxyPools.edit', 'Edit')}
            </GatedButton>
            {onDelete && (
              <GatedButton
                allowed={canDelete}
                reason={deleteReason ?? ''}
                variant="ghost"
                size="sm"
                className="text-destructive hover:text-destructive"
                aria-label={t('proxyPools.deleteNamed', 'Delete {name}', { name: pool.name })}
                onClick={onDelete}
              >
                <Trash2 className="size-4" aria-hidden />
              </GatedButton>
            )}
          </div>
        </div>
      </CardHeader>
      {(children || pool.endpoints.length > 0) && (
        <CardContent className="space-y-4">
          {children}
          {pool.endpoints.length > 0 && (
            <EndpointTable poolId={pool.id} endpoints={pool.endpoints} canWrite={canWrite} />
          )}
        </CardContent>
      )}
    </Card>
  )
}
