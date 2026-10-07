'use client'

import type { SensorGrantSummary } from '@/lib/api/sensor-grant-hooks'
import { AlertTriangle, CheckCircle2 } from 'lucide-react'

import { useTranslation } from '@/context/i18n-provider'
import { cn } from '@/lib/utils'
import { DetailChipList } from '@/features/shared/components/detail-sheet'
import type { Sensor, SensorSdkStatus, SensorVersionStatus } from '@/lib/api/sensor-types'

import { configHealthMeta, configHealthNeedsAttention } from '../lib/config-report'
import { capacityLabel, sensorCapacity, type SensorToolRow } from '../lib/capabilities'
import { formatDurationShort, keyExpiry } from '../lib/format'
import { isOneShotSensor } from '../lib/sensor-state'
import {
  normalizeSensorVersion,
  sensorSdkStatus,
  sensorSdkVersion,
  sensorVersionStatus,
} from '../lib/sensor-version'

/**
 * Cells shared by the sensor table, the phone cards and the drawer, so one
 * value reads the same everywhere. Theme tokens only.
 */

const muted = 'text-muted-foreground'

/** Small tag next to a value ("update", "unsupported", "Platform", ...). */
export function SensorTag({
  tone = 'muted',
  children,
  title,
}: {
  tone?: 'muted' | 'info' | 'warning' | 'destructive' | 'success'
  children: React.ReactNode
  title?: string
}) {
  const tones = {
    muted: 'border text-muted-foreground',
    info: 'bg-info/15 text-info',
    warning: 'bg-warning/15 text-warning',
    destructive: 'bg-destructive/15 text-destructive',
    success: 'text-success ps-0',
  }
  return (
    <span
      title={title}
      className={cn(
        'inline-flex shrink-0 items-center whitespace-nowrap rounded px-1.5 py-px text-[11px] font-medium',
        tones[tone]
      )}
    >
      {children}
    </span>
  )
}

/**
 * The setup health as a tag. By default only the states that need someone
 * (attention, impaired, blocked); `always` shows ok and unknown too.
 */
export function ConfigHealthTag({
  health,
  always = false,
}: {
  health: string | null | undefined
  always?: boolean
}) {
  const { t } = useTranslation()
  if (!always && !configHealthNeedsAttention(health)) return null
  if (always && !health) return null
  const meta = configHealthMeta(health)
  return (
    <SensorTag tone={meta.tone} title={t('sensors.setup.healthTitle', 'Setup checks')}>
      <span data-config-health={health ?? ''}>{t(meta.key, meta.label)}</span>
    </SensorTag>
  )
}

/**
 * The host name a sensor reports, or null when it adds nothing: not reported,
 * or the same as the sensor's name (installs often name the sensor after its
 * host).
 */
export function distinctHostname(sensor: Pick<Sensor, 'name' | 'hostname'>): string | null {
  const host = sensor.hostname?.trim()
  if (!host || host.toLowerCase() === sensor.name.trim().toLowerCase()) return null
  return host
}

/**
 * Name, then host and address on lines of their own (short lines instead of
 * one long one); badges for a platform sensor and the deprecated protocol.
 */
export function SensorNameCell({ sensor, grant }: { sensor: Sensor; grant?: SensorGrantSummary }) {
  const host = distinctHostname(sensor)
  const ip = sensor.ip_address || null
  const fallback = isOneShotSensor(sensor) ? 'CI/CD runner · one-shot' : 'No host reported yet'
  return (
    <div className="flex min-w-0 flex-col">
      <span className="flex min-w-0 items-center gap-1.5">
        <span className="truncate font-medium" data-slot="sensor-name">
          {sensor.name}
        </span>
        {sensor.is_platform_sensor && <SensorTag>Platform</SensorTag>}
        <ProtocolTag sensor={sensor} />
        <ConfigHealthTag health={sensor.config_health} />
        <SensorGrantTags grant={grant} />
      </span>
      {host && (
        <span
          className={cn('truncate text-xs', muted)}
          title="Host name the sensor reports"
          data-slot="sensor-host"
        >
          {host}
        </span>
      )}
      {ip && (
        <span
          className={cn('truncate text-xs tabular-nums', muted)}
          title="Address the platform sees the sensor connect from"
          data-slot="sensor-ip"
        >
          {ip}
        </span>
      )}
      {!sensor.hostname && !ip && <span className={cn('truncate text-xs', muted)}>{fallback}</span>}
    </div>
  )
}

/**
 * Grant flags on the list (RFC-052): the broad grant every sensor that
 * predates per-sensor grants has, and the New trust level (passive work
 * only, no credentials, no results without a job).
 */
export function SensorGrantTags({ grant }: { grant?: SensorGrantSummary }) {
  if (!grant) return null
  return (
    <>
      {grant.legacy_broad && (
        <SensorTag
          tone="warning"
          title="Legacy broad grant: this sensor may do anything a sensor can. Narrow it to the profile that matches what it does."
        >
          Legacy broad grant
        </SensorTag>
      )}
      {grant.trust_level === 'new' && (
        <SensorTag
          tone="info"
          title="New: passive work only, no credentials and no results without a job until an administrator promotes it."
        >
          New
        </SensorTag>
      )}
    </>
  )
}

/**
 * The sensor release that speaks protocol v2, and the date protocol v1 stops
 * (RFC-029: the protocol v1 sunset).
 */
export const PROTOCOL_V2_SENSOR_VERSION = 'v0.5.0'
export const PROTOCOL_V1_SUNSET = '2027-04-01'

/** "v1 · deprecated" when the API reports the sensor still speaks protocol v1 (RFC-029). */
export function ProtocolTag({ sensor }: { sensor: Pick<Sensor, 'protocol'> }) {
  if (!sensor.protocol || (!sensor.protocol.deprecated && sensor.protocol.version >= 2)) return null
  return (
    <SensorTag
      tone="warning"
      title={`Protocol v${sensor.protocol.version} is deprecated. Upgrade the sensor to ${PROTOCOL_V2_SENSOR_VERSION} or later before ${PROTOCOL_V1_SUNSET}.`}
    >
      v{sensor.protocol.version} · deprecated
    </SensorTag>
  )
}

const VERSION_TAG: Record<
  SensorVersionStatus,
  { label: string; tone: 'success' | 'info' | 'destructive' } | null
> = {
  latest: { label: 'latest', tone: 'success' },
  update_available: { label: 'update', tone: 'info' },
  unsupported: { label: 'unsupported', tone: 'destructive' },
  unknown: null,
}

const SDK_TAG: Record<
  SensorSdkStatus,
  { key: string; label: string; tone: 'warning' | 'destructive' } | null
> = {
  current: null,
  unknown: null,
  outdated: { key: 'sensors.version.sdkOutdated', label: 'SDK outdated', tone: 'warning' },
  unsupported: {
    key: 'sensors.version.sdkUnsupported',
    label: 'SDK unsupported',
    tone: 'destructive',
  },
}

export type SensorVersionFields = Pick<
  Sensor,
  | 'version'
  | 'version_status'
  | 'sdk_name'
  | 'sdk_version'
  | 'sdk_status'
  | 'sensor_product'
  | 'sensor_commit'
  | 'sensor_build_time'
>

/** The build facts behind the version, for the tooltip (empty when none). */
export function sensorBuildTooltip(
  sensor: SensorVersionFields,
  t: (key: string, fallback?: string, vars?: Record<string, string | number>) => string,
  locale?: string
): string {
  const lines: string[] = []
  if (sensor.sensor_product) {
    lines.push(t('sensors.version.product', 'Product: {value}', { value: sensor.sensor_product }))
  }
  if (sensor.sensor_commit) {
    lines.push(t('sensors.version.commit', 'Commit: {value}', { value: sensor.sensor_commit }))
  }
  if (sensor.sensor_build_time) {
    const d = new Date(sensor.sensor_build_time)
    if (!Number.isNaN(d.getTime())) {
      lines.push(t('sensors.version.built', 'Built: {value}', { value: d.toLocaleString(locale) }))
    }
  }
  const sdk = sensorSdkVersion(sensor)
  if (sensor.sdk_name || sdk) {
    lines.push(
      t('sensors.version.sdkLine', 'SDK: {value}', {
        value: [sensor.sdk_name, sdk].filter(Boolean).join(' '),
      })
    )
  }
  return lines.join('\n')
}

/**
 * "v0.5.0" over "SDK v0.9.0" (unknown parts left out), how the sensor
 * version compares to the release channel, and a warning when its SDK is
 * outdated or unsupported. The build facts are in the tooltip. The table,
 * the phone cards and the drawer all show the version through this.
 */
export function SensorVersionCell({
  sensor,
  latest,
  min,
  sdkLatest,
  sdkMin,
  showChannelTag = true,
}: {
  sensor: SensorVersionFields
  latest?: string | null
  min?: string | null
  /** Supported SDK range from GET /sensors/stats, for the SDK tag's tooltip. */
  sdkLatest?: string | null
  sdkMin?: string | null
  /** The latest / update / unsupported tag for the sensor release. */
  showChannelTag?: boolean
}) {
  const { t, locale } = useTranslation()
  const v = normalizeSensorVersion(sensor.version)
  const sdk = sensorSdkVersion(sensor)
  if (!v && !sdk) {
    return (
      <span className={cn('text-sm', muted)}>
        {t('sensors.version.notReported', 'Not reported')}
      </span>
    )
  }
  const status = sensorVersionStatus(sensor, latest, min)
  const tag = v && showChannelTag ? VERSION_TAG[status] : null
  const title =
    status === 'update_available' && latest
      ? `${latest} is available`
      : status === 'unsupported' && min
        ? `Older than the minimum supported ${min}`
        : undefined
  const sdkStatus = sensorSdkStatus(sensor)
  const sdkTag = SDK_TAG[sdkStatus]
  const sdkTitle =
    sdkStatus === 'unsupported'
      ? sdkMin
        ? t('sensors.version.sdkUnsupportedMin', 'Older than the minimum supported SDK {min}', {
            min: sdkMin,
          })
        : t('sensors.version.sdkUnsupportedHint', 'Below the minimum supported SDK')
      : sdkStatus === 'outdated'
        ? sdkLatest
          ? t('sensors.version.sdkOutdatedLatest', 'SDK {latest} is available', {
              latest: sdkLatest,
            })
          : t('sensors.version.sdkOutdatedHint', 'A newer SDK is available')
        : undefined
  const build = sensorBuildTooltip(sensor, t, locale)
  // Two short lines instead of one long one: the sensor release with its
  // channel tag, then the SDK (smaller, muted) with its warning.
  return (
    <span className="inline-flex flex-col gap-0.5" title={build || undefined}>
      {v && (
        <span className="inline-flex flex-wrap items-center gap-x-1.5 gap-y-0.5">
          <span className="whitespace-nowrap text-sm tabular-nums" data-slot="sensor-version">
            {v}
          </span>
          {tag && (
            <SensorTag tone={tag.tone} title={title}>
              {tag.label}
            </SensorTag>
          )}
        </span>
      )}
      {sdk && (
        <span className="inline-flex flex-wrap items-center gap-x-1.5 gap-y-0.5">
          <span
            className={cn('whitespace-nowrap text-xs tabular-nums', muted)}
            data-slot="sdk-version"
          >
            {t('sensors.version.sdk', 'SDK')} {sdk}
          </span>
          {sdkTag && (
            <SensorTag tone={sdkTag.tone} title={sdkTitle}>
              {t(sdkTag.key, sdkTag.label)}
            </SensorTag>
          )}
        </span>
      )}
    </span>
  )
}

/** Running jobs over slots, with a small bar. One-shot sensors have none. */
export function SensorJobsCell({ sensor }: { sensor: Sensor }) {
  if (isOneShotSensor(sensor) || sensor.status !== 'active') {
    return <span className={muted}>—</span>
  }
  const current = sensor.current_jobs ?? 0
  // The capacity dispatch uses: the smallest of the sensor's slots, its
  // operator's cap and the limit set on it.
  const max = sensorCapacity(sensor).effective || 0
  const pct = max > 0 ? Math.min(100, (current / max) * 100) : 0
  return (
    <span className="inline-flex items-center gap-2 tabular-nums" title={capacityLabel(sensor)}>
      <span className="h-1.5 w-11 overflow-hidden rounded-full bg-muted" aria-hidden>
        <span className="block h-full bg-info" style={{ width: `${pct}%` }} />
      </span>
      <span className="text-sm">
        {current}/{max}
      </span>
    </span>
  )
}

/** Results waiting on the sensor (its outbox), as it last reported. */
export function SensorOutboxCell({ sensor }: { sensor: Sensor }) {
  const ob = sensor.outbox
  if (!ob && sensor.status !== 'active') return <span className={muted}>—</span>
  if (!ob) {
    return (
      <span className={cn('text-sm', muted)} title="The sensor's SDK does not report an outbox">
        {isOneShotSensor(sensor) ? '—' : 'not reported'}
      </span>
    )
  }
  const lost = ob.dead_letter_count + ob.evicted_count
  if (ob.pending_count === 0 && lost === 0) {
    return <span className={cn('text-sm tabular-nums', muted)}>0</span>
  }
  return (
    <span className="flex flex-col">
      {ob.pending_count > 0 && (
        <span
          className={cn(
            'text-sm tabular-nums',
            sensor.outbox_warning ? 'text-warning' : 'text-foreground'
          )}
        >
          {ob.pending_count.toLocaleString()} queued
        </span>
      )}
      {lost > 0 && (
        <span className="text-sm tabular-nums text-destructive">{lost.toLocaleString()} lost</span>
      )}
      {ob.pending_count > 0 && ob.oldest_age_seconds > 0 && (
        <span className={cn('text-xs', muted)}>
          oldest {formatDurationShort(ob.oldest_age_seconds)}
        </span>
      )}
    </span>
  )
}

/** What the "legacy key" tag means, shown on hover and in the drawer. */
export const LEGACY_KEY_EXPLANATION =
  'This sensor still uses a legacy rda_ key. It renews automatically to the new octs_ format; rda_ keys are retired after enrollment ships.'

/** Tag for a sensor whose current API key is a legacy `rda_` key. */
export function LegacyKeyTag() {
  return (
    <SensorTag tone="muted" title={LEGACY_KEY_EXPLANATION}>
      legacy key
    </SensorTag>
  )
}

/** When the API key stops working, tagged when it is a legacy key. */
export function SensorKeyCell({
  sensor,
  now,
}: {
  sensor: Pick<Sensor, 'key_expires_at' | 'legacy_key'>
  now: number
}) {
  const expiry = <SensorKeyExpiry expiresAt={sensor.key_expires_at} now={now} />
  if (!sensor.legacy_key) return expiry
  return (
    <span className="inline-flex flex-wrap items-center gap-1.5">
      {expiry}
      <LegacyKeyTag />
    </span>
  )
}

function SensorKeyExpiry({
  expiresAt,
  now,
}: {
  expiresAt: string | null | undefined
  now: number
}) {
  const k = keyExpiry(expiresAt, now)
  switch (k.kind) {
    case 'unknown':
      return <span className={muted}>—</span>
    case 'never':
      return <span className={cn('whitespace-nowrap text-sm', muted)}>never expires</span>
    case 'expired':
      return <span className="whitespace-nowrap text-sm text-destructive">expired</span>
    case 'soon':
      return (
        <span className="whitespace-nowrap text-sm text-warning">
          expires in {k.days} {k.days === 1 ? 'day' : 'days'}
        </span>
      )
    default:
      return <span className={cn('whitespace-nowrap text-sm', muted)}>in {k.days} days</span>
  }
}

/** The first tools, then "+N" (all of them on hover). */
export function SensorToolsCell({
  tools,
  max = 2,
}: {
  tools: string[] | null | undefined
  max?: number
}) {
  const list = tools ?? []
  if (list.length === 0) {
    return <span className={cn('text-sm', muted)}>none</span>
  }
  const shown = list.slice(0, max).join(', ')
  const more = list.length - max
  return (
    <span className={cn('text-sm', muted)} title={list.join(', ')}>
      {shown}
      {more > 0 ? ` +${more}` : ''}
    </span>
  )
}

const TOOL_STATUS: Record<
  SensorToolRow['status'],
  { icon: typeof CheckCircle2; className: string; label: string }
> = {
  ready: { icon: CheckCircle2, className: 'text-success', label: 'installed' },
  not_installed: { icon: AlertTriangle, className: 'text-warning', label: 'not installed' },
}

/**
 * A sensor's tools for the drawer: one chip per tool with its version and
 * whether it is installed (an icon, and a tag when it is not usable).
 */
export function SensorToolList({ rows }: { rows: SensorToolRow[] }) {
  return (
    <DetailChipList
      label="Tools"
      chips={rows.map((r) => {
        const st = TOOL_STATUS[r.status]
        return {
          key: r.name,
          data: { tool: r.name, status: r.status },
          icon: st.icon,
          iconClassName: st.className,
          iconLabel: st.label,
          label: r.name,
          muted: r.status !== 'ready',
          meta: (
            <>
              {r.version && <span className={cn('text-xs tabular-nums', muted)}>{r.version}</span>}
              {r.capabilities && r.capabilities.length > 0 && (
                <span
                  className={cn('max-w-48 truncate text-xs', muted)}
                  title={`Serves ${r.capabilities.join(', ')}`}
                  aria-label={`Serves ${r.capabilities.join(', ')}`}
                >
                  {r.capabilities.join(' · ')}
                </span>
              )}
            </>
          ),
          tag:
            r.status === 'not_installed' ? (
              <SensorTag tone="warning">not installed</SensorTag>
            ) : undefined,
        }
      })}
    />
  )
}
