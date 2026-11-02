'use client'

import { useState } from 'react'
import { Plus, Waypoints } from 'lucide-react'
import { toast } from 'sonner'

import { ConfirmDialog } from '@/components/confirm-dialog'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { useTranslation } from '@/context/i18n-provider'
import { EmptyState, GatedButton, ReadOnlyNotice, SettingsSection } from '@/features/shared'
import { useAllSensors } from '@/lib/api/sensor-hooks'
import { Permission, useHasPermission } from '@/lib/permissions'

import {
  invalidateProxyPools,
  updateProxyPool,
  useProxyAssignments,
  useProxyPools,
} from '../api/use-proxy-pools'
import { describeProxyError } from '../lib/errors'
import { defaultPoolImpacts } from '../lib/impact'
import type { ProxyPool } from '../types'
import { ImpactList } from './impact-list'
import { PoolCard } from './pool-card'
import { PoolDialog } from './pool-dialog'

interface DefaultPoolSectionProps {
  /** The pool with is_default, if the organization has one. */
  pool: ProxyPool | undefined
  canWrite: boolean
}

/**
 * Use proxies for scans: the organization default pool, for public targets
 * of the organization's own sensors. The switch is the organization's
 * on/off and saves at once after a confirmation that names what changes
 * (the sensors it would hold back when turning on; direct scanning when
 * turning off). The list is edited in the same dialog as every other pool.
 * The switch needs a proxy first: an enabled empty pool fails every scan
 * closed, and the API refuses it.
 */
export function DefaultPoolSection({ pool, canWrite }: DefaultPoolSectionProps) {
  const { t } = useTranslation()
  const [editing, setEditing] = useState(false)
  const [confirm, setConfirm] = useState<'on' | 'off' | null>(null)
  const [saving, setSaving] = useState(false)
  const on = pool?.enabled ?? false
  const hasProxies = (pool?.endpoints.length ?? 0) > 0

  // Which sensors the default pool holds back, from what they report. Needs
  // the fleet (sensors:read); without it there is no preview.
  const canReadSensors = useHasPermission(Permission.SensorsRead)
  const allPools = useProxyPools()
  const assignments = useProxyAssignments()
  const fleet = useAllSensors(undefined, canReadSensors && hasProxies)
  const impacts =
    hasProxies && fleet.data && assignments.data
      ? defaultPoolImpacts(
          fleet.data.items ?? [],
          assignments.data.items,
          allPools.data?.items ?? []
        )
      : []

  async function apply(enabled: boolean) {
    if (!pool) return
    setSaving(true)
    try {
      await updateProxyPool(pool.id, { enabled })
      await invalidateProxyPools()
      toast.success(
        enabled
          ? t('proxyPools.toast.turnedOn', 'Proxies turned on')
          : t('proxyPools.toast.turnedOff', 'Proxies turned off')
      )
    } catch (e) {
      toast.error(
        describeProxyError(e, t, t('proxyPools.toast.saveFailed', 'Could not save the proxies'))
      )
    } finally {
      setSaving(false)
    }
  }

  const switchId = 'proxy-default-enabled'
  const toggle = (
    <div className="flex items-center gap-3">
      <Switch
        id={switchId}
        checked={on}
        onCheckedChange={(next) => setConfirm(next ? 'on' : 'off')}
        disabled={!canWrite || saving || !hasProxies}
        aria-describedby={!hasProxies ? `${switchId}-why` : undefined}
      />
      <Label htmlFor={switchId}>{t('proxyPools.default.toggle', 'Use proxies for scans')}</Label>
      {!hasProxies && (
        <span id={`${switchId}-why`} className="sr-only">
          {t('proxyPools.default.needsProxyFirst', 'Add a proxy first.')}
        </span>
      )}
    </div>
  )

  return (
    <SettingsSection
      id="default-pool-heading"
      title={t('proxyPools.default.title', 'Default pool')}
      description={t(
        'proxyPools.default.description',
        'Your own sensors send scans to public targets through these proxies. Private addresses are still scanned directly. A sensor can use another pool or go direct on its page. Shared sensors never use your proxies.'
      )}
      actions={toggle}
    >
      {!canWrite && (
        <ReadOnlyNotice
          reason={t(
            'proxyPools.readOnly',
            'You can view proxies but not change them: that needs the sensors:egress:write permission.'
          )}
        />
      )}
      {pool && hasProxies ? (
        <PoolCard
          pool={pool}
          canWrite={canWrite}
          stateBadge={on ? undefined : t('proxyPools.state.off', 'Off')}
          onEdit={() => setEditing(true)}
        >
          {on && <ImpactList impacts={impacts} pending={false} />}
        </PoolCard>
      ) : (
        <EmptyState
          card
          icon={Waypoints}
          title={t('proxyPools.default.emptyTitle', 'No proxies yet')}
          description={t(
            'proxyPools.default.emptyDescription',
            'Add the proxies your sensors should scan public targets through, then turn proxies on. Until then, scans leave directly from each sensor.'
          )}
          action={
            <GatedButton
              allowed={canWrite}
              reason={t(
                'proxyPools.noWrite',
                'You need the sensors:egress:write permission to change pools'
              )}
              size="sm"
              onClick={() => setEditing(true)}
            >
              <Plus className="size-4" aria-hidden />
              {t('proxyPools.default.add', 'Add proxies')}
            </GatedButton>
          }
        />
      )}

      {canWrite && (
        <PoolDialog open={editing} onOpenChange={setEditing} pool={pool ?? null} asDefault />
      )}

      <ConfirmDialog
        open={confirm !== null}
        onOpenChange={(o) => !o && setConfirm(null)}
        title={
          confirm === 'on'
            ? t('proxyPools.default.confirmOnTitle', 'Turn proxies on?')
            : t('proxyPools.default.confirmOffTitle', 'Turn proxies off?')
        }
        desc={
          confirm === 'on'
            ? t(
                'proxyPools.default.confirmOnDesc',
                'Your own sensors send scans to public targets through this pool from their next job. Scans never fall back to a direct connection while it is on.'
              )
            : t(
                'proxyPools.default.confirmOffDesc',
                'Your own sensors scan public targets directly from their own address from their next job. Targets that only allow your proxy addresses will block them.'
              )
        }
        confirmText={
          confirm === 'on'
            ? t('proxyPools.default.turnOn', 'Turn on')
            : t('proxyPools.default.turnOff', 'Turn off')
        }
        handleConfirm={() => {
          const next = confirm === 'on'
          setConfirm(null)
          void apply(next)
        }}
      >
        {confirm === 'on' && <ImpactList impacts={impacts} pending />}
      </ConfirmDialog>
    </SettingsSection>
  )
}
