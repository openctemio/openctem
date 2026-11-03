'use client'

import { useState } from 'react'
import { Plus, Waypoints } from 'lucide-react'
import { toast } from 'sonner'

import { ConfirmDialog } from '@/components/confirm-dialog'
import { useTranslation } from '@/context/i18n-provider'
import { EmptyState, GatedButton, SettingsSection } from '@/features/shared'

import { deleteProxyPool, invalidateProxyPools } from '../api/use-proxy-pools'
import { describeProxyError } from '../lib/errors'
import type { ProxyPool } from '../types'
import { PoolCard } from './pool-card'
import { PoolDialog } from './pool-dialog'
import { confirmName } from '@/lib/confirm-name'

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
    <SettingsSection
      id="more-pools-heading"
      title={t('proxyPools.more.title', 'More pools')}
      description={t(
        'proxyPools.more.description',
        'Pools for one network segment or a few sensors. Pick them on a sensor under Network path.'
      )}
      actions={
        <GatedButton
          allowed={canWrite}
          reason={noWrite}
          size="sm"
          onClick={() => setEditing('new')}
        >
          <Plus className="size-4" aria-hidden />
          {t('proxyPools.more.new', 'New pool')}
        </GatedButton>
      }
    >
      <div className="space-y-3" data-testid="more-pools">
        {pools.length === 0 ? (
          <EmptyState
            card
            icon={Waypoints}
            title={t('proxyPools.more.emptyTitle', 'No other pools')}
            description={t(
              'proxyPools.more.emptyDescription',
              'Add a pool when a sensor in a network segment must reach its targets through its own proxy.'
            )}
          />
        ) : (
          pools.map((p) => (
            <PoolCard
              key={p.id}
              pool={p}
              canWrite={canWrite}
              stateBadge={p.enabled ? undefined : t('proxyPools.state.disabled', 'Disabled')}
              onEdit={() => setEditing(p)}
              onDelete={() => setDeleting(p)}
              canDelete={canDelete && p.assigned_sensors === 0}
              deleteReason={canDelete ? inUse : noDelete}
            />
          ))
        )}
      </div>

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
        title={t('proxyPools.deleteTitle', 'Delete the pool "{name}"?', {
          name: deleting?.name ?? '',
        })}
        desc={t(
          'proxyPools.deleteDesc',
          'The pool and its proxies are deleted. Their stored credentials are erased.'
        )}
        confirmText={t('proxyPools.deleteButton', 'Delete pool')}
        destructive
        typeToConfirm={deleting ? confirmName(deleting.name, deleting.id) : undefined}
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
    </SettingsSection>
  )
}
