'use client'

import { useTranslation } from '@/context/i18n-provider'
import { MetricStrip, type MetricStripItem } from '@/features/shared'
import { cn } from '@/lib/utils'

import {
  scanningSensorLine,
  type AttentionKind,
  type FleetSummary,
  type ReleaseChannel,
} from '../lib/fleet'
import { PROTOCOL_V1_SUNSET, PROTOCOL_V2_SENSOR_VERSION } from './sensor-cells'

const ATTENTION_WORDS: Record<AttentionKind, string> = {
  offline: 'sensors.health.attention.offline',
  backlog: 'sensors.health.attention.backlog',
  key: 'sensors.health.attention.key',
  version: 'sensors.health.attention.version',
  sdk: 'sensors.health.attention.sdk',
  heartbeat: 'sensors.health.attention.heartbeat',
  tools: 'sensors.health.attention.tools',
  content: 'sensors.health.attention.content',
  preflight: 'sensors.health.attention.preflight',
  posture: 'sensors.health.attention.posture',
  error: 'sensors.health.attention.error',
}

/** The fleet's state mix as one small bar, with a legend (no colour-only meaning). */
function FleetBar({ summary }: { summary: FleetSummary }) {
  const { t } = useTranslation()
  const s = summary.byState
  const parts = [
    { key: 'online', label: t('sensors.health.bar.online'), n: s.online, className: 'bg-success' },
    {
      key: 'warn',
      label: t('sensors.health.bar.warn'),
      n: s.degraded + s.late + s.stale,
      className: 'bg-warning',
    },
    {
      key: 'offline',
      label: t('sensors.health.bar.offline'),
      n: s.offline + s.never_connected,
      className: 'bg-destructive',
    },
    { key: 'idle', label: t('sensors.health.bar.idle'), n: s.idle, className: 'bg-info' },
    {
      key: 'off',
      label: t('sensors.health.bar.off'),
      n: s.disabled + s.revoked,
      className: 'bg-border',
    },
  ].filter((p) => p.n > 0)
  if (parts.length === 0) return null
  const label = parts.map((p) => `${p.n} ${p.label.toLowerCase()}`).join(', ')
  return (
    <span className="block">
      <span
        role="img"
        aria-label={label}
        className="mt-1 flex h-1.5 gap-0.5 overflow-hidden rounded-full"
      >
        {parts.map((p) => (
          <span key={p.key} className={cn('block h-full', p.className)} style={{ flex: p.n }} />
        ))}
      </span>
      <span className="mt-1.5 flex flex-wrap gap-x-3 gap-y-0.5" aria-hidden>
        {parts.map((p) => (
          <span key={p.key} className="inline-flex items-center gap-1 whitespace-nowrap">
            <span className={cn('size-2 rounded-sm', p.className)} />
            {p.label} <span className="font-medium tabular-nums text-foreground">{p.n}</span>
          </span>
        ))}
      </span>
    </span>
  )
}

export interface FleetHealthStripProps {
  summary: FleetSummary
  channel: ReleaseChannel
  loading?: boolean
  /** The table shows only the sensors that are not connected. */
  notConnectedActive: boolean
  onToggleNotConnected: () => void
  attentionActive: boolean
  onToggleAttention: () => void
  updatesActive: boolean
  onToggleUpdates: () => void
  zoneGroupingActive: boolean
  onToggleZoneGrouping: () => void
  protocolV1Active: boolean
  onToggleProtocolV1: () => void
  className?: string
}

/**
 * Fleet health, the first thing on the page: how many sensors can take work,
 * what needs attention, version drift, zone coverage and job slots. The
 * clickable metrics filter (or group) the table below: Fleet health to the
 * sensors that are not connected, Needs attention, Updates, Zones (grouping)
 * and protocol v1. Jobs stays a number: no subset of sensors answers it.
 */
export function FleetHealthStrip({
  summary,
  channel,
  loading,
  notConnectedActive,
  onToggleNotConnected,
  attentionActive,
  onToggleAttention,
  updatesActive,
  onToggleUpdates,
  zoneGroupingActive,
  onToggleZoneGrouping,
  protocolV1Active,
  onToggleProtocolV1,
  className,
}: FleetHealthStripProps) {
  const { t } = useTranslation()
  const scanner = scanningSensorLine(channel)
  const s = summary.byState
  const notConnected = s.stale + s.offline + s.never_connected
  const items: MetricStripItem[] = [
    {
      key: 'health',
      label: t('sensors.health.fleet'),
      value: summary.canTakeJobs,
      hint: t('sensors.health.canTakeJobs', undefined, { count: summary.enabled }),
      detail: <FleetBar summary={summary} />,
      // Filters to the sensors that are not connected, when there are any.
      ...(notConnected > 0 || notConnectedActive
        ? { onClick: onToggleNotConnected, active: notConnectedActive }
        : {}),
    },
    {
      key: 'attention',
      label: t('sensors.health.attention'),
      value: summary.needsAttention,
      tone: 'warning',
      detail:
        summary.needsAttention > 0
          ? summary.attentionKinds.map((k) => t(ATTENTION_WORDS[k])).join(', ')
          : t('sensors.health.nothingToFix'),
      onClick: onToggleAttention,
      active: attentionActive,
    },
    {
      key: 'updates',
      label: t('sensors.health.updates'),
      value: summary.updates,
      hint: scanner.latest
        ? t('sensors.health.latest', undefined, { version: scanner.latest })
        : undefined,
      detail:
        summary.unsupported > 0 ? (
          <span className="text-destructive">
            {t('sensors.health.belowProductMin', undefined, { count: summary.unsupported })}
          </span>
        ) : (channel.products?.length ?? 0) > 0 ? (
          summary.updates === 0 ? (
            t('sensors.health.allLatest')
          ) : (
            t('sensors.health.olderRun')
          )
        ) : (
          t('sensors.health.noChannel')
        ),
      onClick: onToggleUpdates,
      active: updatesActive,
    },
  ]
  if (summary.zones) {
    const z = summary.zones
    items.push({
      key: 'zones',
      label: t('sensors.health.zones'),
      value: z.covered,
      hint: t('sensors.health.ofZones', undefined, { count: z.total }),
      detail:
        z.uncovered.length > 0 ? (
          <span className="text-destructive">
            {z.uncovered.length === 1
              ? t('sensors.health.zoneUncovered.one', undefined, { zone: z.uncovered[0] })
              : t('sensors.health.zoneUncovered.other', undefined, { count: z.uncovered.length })}
          </span>
        ) : (
          t('sensors.health.zonesCovered')
        ),
      onClick: onToggleZoneGrouping,
      active: zoneGroupingActive,
    })
  }
  // Only while some sensor still speaks the deprecated protocol (RFC-029).
  if (summary.protocolV1 > 0) {
    items.push({
      key: 'protocol',
      label: t('sensors.health.protocolV1'),
      value: summary.protocolV1,
      tone: 'warning',
      detail: t('sensors.health.upgrade', undefined, {
        version: PROTOCOL_V2_SENSOR_VERSION,
        date: PROTOCOL_V1_SUNSET,
      }),
      onClick: onToggleProtocolV1,
      active: protocolV1Active,
    })
  }
  items.push({
    key: 'jobs',
    label: t('sensors.health.jobs'),
    value: summary.jobsRunning,
    hint: t('sensors.health.slots', undefined, { count: summary.jobSlots }),
    detail: t(
      summary.canTakeJobs === 1 ? 'sensors.health.onSensors.one' : 'sensors.health.onSensors.other',
      undefined,
      { count: summary.canTakeJobs }
    ),
  })
  return <MetricStrip className={className} loading={loading} items={items} />
}
