'use client'

/**
 * "What still stops this sensor from scanning": one checklist (research/466
 * D10), shown on the sensor sheet, at the end of Add sensor and in New scan.
 * The items come from GET /sensors/{id}/readiness in the order to fix them;
 * each blocked item offers the one action that clears it, or says who may
 * take it. Every action goes through the gate it belongs to (the grant, the
 * scope service, the Zones page, the host): the checklist only points.
 */

import { useState } from 'react'
import {
  AlertTriangle,
  CheckCircle2,
  CircleDashed,
  Clock,
  ExternalLink,
  Loader2,
} from 'lucide-react'
import { toast } from 'sonner'

import Link from '@/components/link'
import { SafeExternalLink } from '@/components/safe-external-link'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { useTranslation } from '@/context/i18n-provider'
import { reportBulkResult } from '@/features/scope/components/add-to-scope-action'
import { createScopeTargetsBulk, invalidateScopeCache } from '@/features/scope/api/use-scope-api'
import { getErrorMessage } from '@/lib/api/error-handler'
import { grantUpdateRequest, updateSensorGrant, useSensorGrant } from '@/lib/api/sensor-grant-hooks'
import {
  useSensorReadiness,
  type ReadinessItem,
  type ReadinessState,
} from '@/lib/api/sensor-readiness-hooks'
import { Permission, useHasPermission } from '@/lib/permissions'
import { cn } from '@/lib/utils'

import { Snippet } from './sensor-install-snippets'

/** The scope entry type of one range. */
function scopeTypeOf(range: string): 'cidr' | 'ip_range' | 'ip_address' {
  if (range.includes('-')) return 'ip_range'
  if (range.includes('/') && !range.endsWith('/32') && !range.endsWith('/128')) return 'cidr'
  return 'ip_address'
}

/** The address of a single-host prefix, as a scope entry wants it. */
function scopePatternOf(range: string): string {
  return range.endsWith('/32') || range.endsWith('/128')
    ? range.slice(0, range.lastIndexOf('/'))
    : range
}

const STATE_ICON: Record<ReadinessState, typeof CheckCircle2> = {
  ok: CheckCircle2,
  blocked: AlertTriangle,
  waiting: Clock,
  unknown: CircleDashed,
  not_applicable: CircleDashed,
}

const STATE_COLOR: Record<ReadinessState, string> = {
  ok: 'text-success',
  blocked: 'text-warning',
  waiting: 'text-info',
  unknown: 'text-muted-foreground',
  not_applicable: 'text-muted-foreground',
}

export interface SensorReadinessChecklistProps {
  sensorId: string
  /** Name the sensor in the heading (New scan lists several). */
  sensorName?: string
  /** Hide the items that are fine or do not apply (New scan). */
  blockersOnly?: boolean
  className?: string
}

export function SensorReadinessChecklist({
  sensorId,
  sensorName,
  blockersOnly,
  className,
}: SensorReadinessChecklistProps) {
  const { t } = useTranslation()
  const { data, error, isLoading, mutate } = useSensorReadiness(sensorId)

  if (isLoading) return <Skeleton className={cn('h-24 w-full', className)} />
  if (error || !data) {
    return (
      <p className={cn('text-sm text-muted-foreground', className)} role="status">
        {t('sensors.readiness.loadError')}
      </p>
    )
  }
  const items = data.items.filter(
    (it) => it.state !== 'not_applicable' && (!blockersOnly || it.state !== 'ok')
  )
  const title = sensorName
    ? t('sensors.readiness.titleFor', undefined, { name: sensorName })
    : t('sensors.readiness.title')

  return (
    <section
      className={cn('space-y-2', className)}
      aria-label={title}
      data-testid="sensor-readiness"
    >
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <h4 className="text-sm font-semibold">{title}</h4>
        <span
          className={cn('text-xs', data.ready ? 'text-success' : 'text-muted-foreground')}
          aria-live="polite"
        >
          {data.ready ? t('sensors.readiness.ready') : t('sensors.readiness.notReady')}
        </span>
      </div>
      {items.length > 0 && (
        <ol className="divide-y rounded-lg border">
          {items.map((it) => (
            <ReadinessRow
              key={it.key}
              item={it}
              sensorId={sensorId}
              onChanged={() => void mutate()}
            />
          ))}
        </ol>
      )}
    </section>
  )
}

function ReadinessRow({
  item,
  sensorId,
  onChanged,
}: {
  item: ReadinessItem
  sensorId: string
  onChanged: () => void
}) {
  const { t } = useTranslation()
  const Icon = STATE_ICON[item.state]
  const params = { count: item.count ?? 0 }
  return (
    <li className="space-y-2 px-3 py-2.5 text-sm" data-testid={`readiness-${item.key}`}>
      <div className="flex items-start gap-2">
        <Icon className={cn('mt-0.5 h-4 w-4 shrink-0', STATE_COLOR[item.state])} aria-hidden />
        <div className="min-w-0 flex-1">
          <p className="font-medium">{t(`sensors.readiness.item.${item.key}.title`)}</p>
          <p className="text-muted-foreground">
            <span className="sr-only">{t(`sensors.readiness.state.${item.state}`)}: </span>
            {t(
              `sensors.readiness.item.${item.key}.${item.state}`,
              t(`sensors.readiness.state.${item.state}`),
              params
            )}
          </p>
        </div>
      </div>
      {item.fix && item.state !== 'ok' && (
        <div className="ps-6">
          <ReadinessFixAction item={item} sensorId={sensorId} onChanged={onChanged} />
        </div>
      )}
    </li>
  )
}

function ReadinessFixAction({
  item,
  sensorId,
  onChanged,
}: {
  item: ReadinessItem
  sensorId: string
  onChanged: () => void
}) {
  const { t } = useTranslation()
  const fix = item.fix!
  if (!fix.allowed) {
    return (
      <p className="text-xs text-muted-foreground">
        {t('sensors.readiness.needsPermission', undefined, { permission: fix.permission ?? '' })}
      </p>
    )
  }
  switch (fix.action) {
    case 'promote':
      return <PromoteAction sensorId={sensorId} onDone={onChanged} />
    case 'add_scope':
      return <AddScopeAction patterns={fix.patterns ?? []} onDone={onChanged} />
    case 'add_zone':
      return (
        <Button asChild variant="outline" size="sm">
          <Link href="/sensors?tab=zones">{t('sensors.readiness.fix.add_zone')}</Link>
        </Button>
      )
    case 'enable_private':
    case 'kill_switch_off':
      return (
        <div className="space-y-1.5">
          <p className="text-xs text-muted-foreground">
            {t(`sensors.readiness.fix.${fix.action}`)}
          </p>
          {fix.host_line && (
            <Snippet text={fix.host_line} label={t(`sensors.readiness.fix.${fix.action}`)} />
          )}
        </div>
      )
    case 'sandbox_docs':
      return (
        <SafeExternalLink
          href={fix.docs}
          className="inline-flex items-center gap-1 text-xs font-medium underline-offset-4 hover:underline"
        >
          {t('sensors.readiness.fix.sandbox_docs')}
          <ExternalLink className="h-3 w-3" aria-hidden />
        </SafeExternalLink>
      )
    case 'show_install':
      return (
        <p className="text-xs text-muted-foreground">{t('sensors.readiness.fix.show_install')}</p>
      )
    default:
      return null
  }
}

/** "Trust this sensor": the same grant change, confirm and audit as the Grant section. */
function PromoteAction({ sensorId, onDone }: { sensorId: string; onDone: () => void }) {
  const { t } = useTranslation()
  const { data: grant, mutate } = useSensorGrant(sensorId)
  const [open, setOpen] = useState(false)
  const [busy, setBusy] = useState(false)
  const promote = async () => {
    if (!grant) return
    setBusy(true)
    try {
      const next = await updateSensorGrant(
        sensorId,
        grantUpdateRequest(grant, { trust_level: 'trusted' })
      )
      await mutate(next, { revalidate: false })
      toast.success(t('sensors.grantSection.promoted'))
      setOpen(false)
      onDone()
    } catch (err) {
      toast.error(getErrorMessage(err, t('sensors.readiness.fixFailed')))
    } finally {
      setBusy(false)
    }
  }
  return (
    <>
      <Button size="sm" variant="outline" disabled={!grant} onClick={() => setOpen(true)}>
        {t('sensors.readiness.fix.promote')}
      </Button>
      <ConfirmDialog
        open={open}
        onOpenChange={setOpen}
        title={t('confirm.sensor.promoteTitle')}
        desc={t('confirm.sensor.promoteDesc')}
        confirmText={t('confirm.sensor.promote')}
        isLoading={busy}
        handleConfirm={() => void promote()}
      />
    </>
  )
}

/** "Add to scope": the ranges as scope entries, through the scope service and its approvals. */
function AddScopeAction({ patterns, onDone }: { patterns: string[]; onDone: () => void }) {
  const { t } = useTranslation()
  const [busy, setBusy] = useState(false)
  const add = async () => {
    setBusy(true)
    try {
      const res = await createScopeTargetsBulk({
        items: patterns.map((p) => ({ target_type: scopeTypeOf(p), pattern: scopePatternOf(p) })),
        reason: t('sensors.readiness.scopeReason'),
      })
      reportBulkResult(t, res)
      await invalidateScopeCache()
      onDone()
    } catch (err) {
      toast.error(getErrorMessage(err, t('sensors.readiness.fixFailed')))
    } finally {
      setBusy(false)
    }
  }
  return (
    <div className="space-y-1.5">
      <p className="font-mono text-xs break-all">{patterns.join(', ')}</p>
      <Button
        size="sm"
        variant="outline"
        onClick={() => void add()}
        disabled={busy || patterns.length === 0}
      >
        {busy && <Loader2 className="h-4 w-4 animate-spin" aria-hidden />}
        {t('sensors.readiness.fix.add_scope')}
      </Button>
    </div>
  )
}

/** At most this many sensors of a zone get their checklist in New scan. */
export const ZONE_READINESS_MAX = 3

/**
 * New scan: what still stops the sensors of the chosen zone, blockers only.
 * Hidden without sensors:read (the route refuses it anyway).
 */
export function ZoneSensorsReadiness({ sensorIds }: { sensorIds: string[] }) {
  const { t } = useTranslation()
  const canRead = useHasPermission(Permission.SensorsRead)
  if (!canRead) return null
  if (sensorIds.length === 0) {
    return (
      <p className="mt-1 text-xs text-warning" data-testid="zone-no-sensor">
        {t('sensors.readiness.zoneNoSensor')}
      </p>
    )
  }
  return (
    <div className="mt-2 space-y-3" data-testid="zone-readiness">
      {sensorIds.slice(0, ZONE_READINESS_MAX).map((id) => (
        <SensorReadinessChecklist key={id} sensorId={id} blockersOnly />
      ))}
    </div>
  )
}
