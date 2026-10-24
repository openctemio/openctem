'use client'

import { useState } from 'react'
import { Plus, Trash2, Waypoints } from 'lucide-react'
import { toast } from 'sonner'

import { nameToTypeToConfirm } from '@/components/confirm-name'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { Badge } from '@/components/ui/badge'
import { Card, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { useTranslation } from '@/context/i18n-provider'
import { EmptyState, GatedButton } from '@/features/shared'

import { deleteProxyPool, invalidateProxyPools } from '../api/use-proxy-pools'
import { describeProxyError } from '../lib/errors'
import type { ProxyPool } from '../types'
import { EndpointTable } from './endpoint-table'
import { PoolDialog } from './pool-dialog'

interface MorePoolsSectionProps {
  pools: ProxyPool[]
  canWrite: boolean
  canDelete: boolean
}

/** The pools other than the organization default; sensors pick them on their own pages. */
export function MorePoolsSection({ pools, canWrite, canDelete }: MorePoolsSectionProps) {
  const { t } = useTranslation()
  const [editing, setEditing] = useState<ProxyPool | 'new' | null>(null)
  const [deleting, setDeleting] = useState<ProxyPool | null>(null)
  const noWrite = t(
    'proxyPools.noWrite',
    'You need the sensors:egress:write permission to change pools'
  )
  const noDelete = t(
    'proxyPools.noDelete',
    'You need the sensors:egress:delete permission to delete pools'
  )

  const inUse = t(
    'proxyPools.deleteInUse',
    'Sensors still use this pool. Set their network path to another pool, Direct or Inherit first.'
  )

  return (
    <section aria-labelledby="more-pools-heading" className="space-y-3" data-testid="more-pools">
      <div className="flex flex-wrap items-end justify-between gap-2">
        <div>
          <h2 id="more-pools-heading" className="text-base font-semibold">
            {t('proxyPools.more.title', 'More pools')}
          </h2>
          <p className="text-sm text-muted-foreground">
            {t(
              'proxyPools.more.description',
              'Pools for one network segment or a few sensors. Pick them on a sensor under Network path.'
            )}
          </p>
        </div>
        <GatedButton
          allowed={canWrite}
          reason={noWrite}
          size="sm"
          onClick={() => setEditing('new')}
        >
          <Plus className="size-4" aria-hidden />
          {t('proxyPools.more.new', 'New pool')}
        </GatedButton>
      </div>

      {pools.length === 0 ? (
        <EmptyState
          icon={Waypoints}
          title={t('proxyPools.more.emptyTitle', 'No other pools')}
          description={t(
            'proxyPools.more.emptyDescription',
            'Add a pool when a sensor in a network segment must reach its targets through its own proxy.'
          )}
        />
      ) : (
        pools.map((p) => (
          <Card key={p.id} data-testid="pool-row">
            <CardHeader className="space-y-3">
              <div className="flex flex-wrap items-start justify-between gap-2">
                <div className="min-w-0 space-y-1">
                  <CardTitle className="flex flex-wrap items-center gap-2 text-base">
                    <span className="break-words">{p.name}</span>
                    {!p.enabled && (
                      <Badge variant="secondary" className="font-normal">
                        {t('proxyPools.state.disabled', 'Disabled')}
                      </Badge>
                    )}
                  </CardTitle>
                  <CardDescription>
                    {p.assigned_sensors === 1
                      ? t('proxyPools.assignedSensors.one', '{count} sensor assigned', {
                          count: p.assigned_sensors,
                        })
                      : t('proxyPools.assignedSensors.other', '{count} sensors assigned', {
                          count: p.assigned_sensors,
                        })}
                    {p.description ? ` · ${p.description}` : ''}
                  </CardDescription>
                </div>
                <div className="flex gap-2">
                  <GatedButton
                    allowed={canWrite}
                    reason={noWrite}
                    variant="outline"
                    size="sm"
                    onClick={() => setEditing(p)}
                  >
                    {t('proxyPools.edit', 'Edit')}
                  </GatedButton>
                  <GatedButton
                    allowed={canDelete && p.assigned_sensors === 0}
                    reason={canDelete ? inUse : noDelete}
                    variant="ghost"
                    size="sm"
                    className="ms-3 text-destructive hover:text-destructive"
                    aria-label={t('proxyPools.deleteNamed', 'Delete {name}', { name: p.name })}
                    onClick={() => setDeleting(p)}
                  >
                    <Trash2 className="size-4" aria-hidden />
                  </GatedButton>
                </div>
              </div>
              {p.endpoints.length > 0 && (
                <EndpointTable poolId={p.id} endpoints={p.endpoints} canWrite={canWrite} />
              )}
            </CardHeader>
          </Card>
        ))
      )}

      {canWrite && (
        <PoolDialog
          open={!!editing}
          onOpenChange={(o) => !o && setEditing(null)}
          pool={editing === 'new' ? null : editing}
        />
      )}

      <ConfirmDialog
        open={!!deleting}
        onOpenChange={(o) => !o && setDeleting(null)}
        title={t('confirm.proxyPool.deleteTitle', undefined, { name: deleting?.name ?? '' })}
        desc={t('confirm.proxyPool.deleteDesc')}
        confirmText={t('confirm.proxyPool.deleteBtn')}
        destructive
        typeToConfirm={deleting ? nameToTypeToConfirm(deleting.name, deleting.id) : undefined}
        handleConfirm={() => {
          const target = deleting
          setDeleting(null)
          if (!target) return
          deleteProxyPool(target.id)
            .then(async () => {
              toast.success(t('proxyPools.toast.deleted', 'Pool deleted'))
              await invalidateProxyPools()
            })
            .catch((e: unknown) =>
              toast.error(
                describeProxyError(
                  e,
                  t,
                  t('proxyPools.toast.deleteFailed', 'Could not delete the pool')
                )
              )
            )
        }}
      />
    </section>
  )
}
