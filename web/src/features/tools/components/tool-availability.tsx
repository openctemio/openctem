'use client'

/**
 * Shared pieces for a tool's availability (api tool-availability.md): the
 * status pill, the "n/m online" sensors cell with its sensor list, and the
 * sensor list itself. Used by the Tools page table and detail sheet; the
 * pickers use toolUnavailableReason from ../lib/availability.
 */

import { Server } from 'lucide-react'

import { useTranslation } from '@/context/i18n-provider'
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover'
import { TonePill } from '@/features/shared'
import type {
  ToolAvailabilityInfo,
  ToolAvailabilityItem,
  ToolAvailabilitySensor,
} from '@/lib/api/tool-types'
import { cn } from '@/lib/utils'

import {
  TOOL_STATUS_META,
  sensorsLabel,
  toolExclusionLabel,
  toolStatusDescription,
  toolStatusLabel,
  toolUnavailableReason,
} from '../lib/availability'

/** The derived status as a pill; the tooltip says what it means and why. */
export function ToolStatusBadge({
  item,
  className,
}: {
  item: ToolAvailabilityItem
  className?: string
}) {
  const meta = TOOL_STATUS_META[item.status]
  const { t } = useTranslation()
  const reason = toolUnavailableReason(item, t)
  const description = toolStatusDescription(item.status, t)
  return (
    <TonePill
      tone={meta.tone}
      label={toolStatusLabel(item.status, t)}
      title={reason ? `${description} ${reason}.` : description}
      state={item.status}
      className={className}
    />
  )
}

const TIER_LABEL = { T0: 'passive', T1: 'active', T2: 'intrusive' } as const

/** A tier word ("passive") in the viewer's language. */
function tierWord(
  tier: keyof typeof TIER_LABEL,
  t: (key: string, fallback?: string) => string
): string {
  return t(`scans.tools.tier.${tier}`, TIER_LABEL[tier])
}

/**
 * The trust and the tier the platform assigns a tool (RFC-055 §5). An
 * operator-installed copy is unverified and runs only as T2; nothing shows
 * for a tool no sensor reports a contract for.
 */
export function ToolTrustBadge({
  item,
  className,
}: {
  item: Pick<ToolAvailabilityInfo, 'trust' | 'tier'>
  className?: string
}) {
  const { t } = useTranslation()
  if (!item.trust && !item.tier) return null
  const tier = item.tier ? `${item.tier} ${tierWord(item.tier, t)}` : ''
  if (item.trust === 'unverified') {
    return (
      <TonePill
        tone="warning"
        label={
          item.tier
            ? t('scans.tools.trust.unverifiedTier', 'Unverified, {tier}', { tier: item.tier })
            : t('scans.tools.trust.unverified', 'Unverified')
        }
        title={t(
          'scans.tools.trust.unverifiedTitle',
          "Installed by a sensor's operator and not verified: it runs only as tier T2 (intrusive), under a grant that allows T2."
        )}
        state="unverified"
        className={className}
      />
    )
  }
  return (
    <TonePill
      tone="muted"
      label={item.tier ?? t('scans.tools.trust.builtIn', 'Built in')}
      title={
        item.trust === 'builtin'
          ? t(
              'scans.tools.trust.builtInTitle',
              'Built into the sensor. The platform runs it as tier {tier}.',
              {
                tier,
              }
            )
          : t('scans.tools.trust.tierTitle', 'The platform runs it as tier {tier}.', { tier })
      }
      state={item.trust ?? 'tier'}
      className={className}
    />
  )
}

/** One sensor row: name, state, zones, version and why it may not run the tool. */
function SensorRow({ sensor }: { sensor: ToolAvailabilitySensor }) {
  const { t } = useTranslation()
  return (
    <li className="flex items-start justify-between gap-3 py-1.5">
      <div className="min-w-0">
        <p className={cn('truncate text-sm', !sensor.online && 'text-muted-foreground')}>
          {sensor.name}
        </p>
        <p className="truncate text-xs text-muted-foreground">
          {sensor.online
            ? t('scans.tools.sensor.online', 'Online')
            : t(`sensors.state.${sensor.state}.label`, sensor.state.replace(/_/g, ' '))}
          {sensor.zones.length > 0 && `, ${sensor.zones.map((z) => z.name).join(', ')}`}
        </p>
        {sensor.trust === 'unverified' && (
          <p className="text-xs text-warning">
            {t('scans.tools.sensor.unverified', 'Operator-installed copy (unverified, T2)')}
          </p>
        )}
        {sensor.excluded && (
          <p className="text-xs text-warning" title={sensor.excluded_detail}>
            {t('scans.tools.sensor.excluded', 'Has it, but {reason}', {
              reason: toolExclusionLabel(sensor.excluded, t),
            })}
          </p>
        )}
      </div>
      {sensor.version && (
        <span className="shrink-0 text-xs tabular-nums text-muted-foreground">
          {sensor.version}
        </span>
      )}
    </li>
  )
}

/** The sensors that report a tool, online first (as the API orders them). */
export function ToolSensorList({
  item,
  className,
}: {
  item: Pick<ToolAvailabilityItem, 'sensors' | 'sensors_total' | 'sensors_excluded'>
  className?: string
}) {
  const { t } = useTranslation()
  if (item.sensors.length === 0) {
    const n = item.sensors_total + item.sensors_excluded
    return (
      <p className={cn('text-sm text-muted-foreground', className)}>
        {n === 0
          ? t('scans.tools.sensors.noneReport', 'No sensor reports this tool.')
          : t(
              'scans.tools.sensors.reportNoAccess',
              '{count, plural, one {# sensor reports} other {# sensors report}} this tool. Listing them needs permission to read sensors.',
              { count: n }
            )}
      </p>
    )
  }
  return (
    <ul
      className={cn('divide-y', className)}
      aria-label={t('scans.tools.sensors.withTool', 'Sensors with this tool')}
    >
      {item.sensors.map((s) => (
        <SensorRow key={s.id} sensor={s} />
      ))}
    </ul>
  )
}

/** "n/m online" with the sensor list in a popover. */
export function ToolSensorsCell({ item }: { item: ToolAvailabilityItem }) {
  const { t } = useTranslation()
  const label = sensorsLabel(item, t)
  const reported = item.sensors_total + item.sensors_excluded
  if (reported === 0) {
    return (
      <span className="text-xs text-muted-foreground">{t('scans.tools.sensors.none', 'none')}</span>
    )
  }
  return (
    <Popover>
      <PopoverTrigger asChild>
        <button
          type="button"
          className="inline-flex items-center gap-1.5 rounded px-1 text-sm tabular-nums hover:bg-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
          aria-label={t('scans.tools.sensors.withNameLabel', 'Sensors with {name}: {label}', {
            name: item.name,
            label,
          })}
          onClick={(e) => e.stopPropagation()}
        >
          <Server className="h-3.5 w-3.5 text-muted-foreground" aria-hidden />
          <span className={cn(item.sensors_online === 0 && 'text-muted-foreground')}>{label}</span>
          {item.sensors_excluded > 0 && (
            <span className="text-xs text-warning">
              {t('scans.tools.sensors.notAllowed', '+{count} not allowed', {
                count: item.sensors_excluded,
              })}
            </span>
          )}
        </button>
      </PopoverTrigger>
      <PopoverContent className="w-80 p-3" onClick={(e) => e.stopPropagation()}>
        <p className="mb-1 text-xs font-medium text-muted-foreground">
          {t('scans.tools.sensors.withName', 'Sensors with {name}', { name: item.name })}
        </p>
        <ToolSensorList item={item} />
      </PopoverContent>
    </Popover>
  )
}
