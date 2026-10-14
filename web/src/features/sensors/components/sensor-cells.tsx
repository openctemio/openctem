'use client'

import type { SensorGrantSummary } from '@/lib/api/sensor-grant-hooks'
import { AlertTriangle, CheckCircle2, ShieldAlert } from 'lucide-react'

import { useTranslation } from '@/context/i18n-provider'
import { cn } from '@/lib/utils'
import { DetailChipList } from '@/features/shared/components/detail-sheet'
import type { Sensor, SensorSdkStatus, SensorVersionStatus } from '@/lib/api/sensor-types'

import { configHealthMeta, configHealthNeedsAttention } from '../lib/config-report'
import { capacityLabel, sensorCapacity, type SensorToolRow } from '../lib/capabilities'
import { formatDurationShort, keyExpiry } from '../lib/format'
import { postureIssues } from '../lib/posture'
import { isOneShotSensor } from '../lib/sensor-state'
import type { ReleaseChannel } from '../lib/fleet'
import {
  normalizeSensorVersion,
  releaseLineOf,
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
 * A warning tag on the sensor list and cards for a sensor the platform flags
 * as unhardened; the title lists the fixes. Nothing for a hardened sensor or
 * an API without the posture.
 */
export function SensorPostureTag({ sensor }: { sensor: Pick<Sensor, 'posture'> }) {
  const { t } = useTranslation()
  const issues = postureIssues(sensor)
  if (issues.length === 0) return null
  const title = issues.map((i) => t(i.fixKey, i.fix)).join('\n')
  return (
    <SensorTag tone="warning" title={title}>
      <span data-slot="sensor-posture-tag" className="inline-flex items-center gap-1">
        <ShieldAlert className="h-3 w-3" aria-hidden />
        {t('sensors.posture.tag', 'Unhardened')}
      </span>
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
  const { t } = useTranslation()
  const host = distinctHostname(sensor)
  const ip = sensor.ip_address || null
  const fallback = isOneShotSensor(sensor) ? t('sensors.cells.oneShot') : t('sensors.cells.noHost')
  return (
    <div className="flex min-w-0 flex-col">
      <span className="flex min-w-0 items-center gap-1.5">
        <span className="truncate font-medium" data-slot="sensor-name">
          {sensor.name}
        </span>
        <ProtocolTag sensor={sensor} />
        <ConfigHealthTag health={sensor.config_health} />
        <SensorPostureTag sensor={sensor} />
        <SensorGrantTags grant={grant} />
      </span>
      {host && (
        <span
          className={cn('truncate text-xs', muted)}
          title={t('sensors.cells.hostTitle')}
          data-slot="sensor-host"
        >
          {host}
        </span>
      )}
      {ip && (
        <span
          className={cn('truncate text-xs tabular-nums', muted)}
          title={t('sensors.cells.ipTitle')}
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
  const { t } = useTranslation()
  if (!grant) return null
  return (
    <>
      {grant.legacy_broad && (
        <SensorTag tone="warning" title={t('sensors.cells.legacyBroadTitle')}>
          {t('sensors.grantEdit.profile.legacy-broad')}
        </SensorTag>
      )}
      {grant.trust_level === 'new' && (
        <SensorTag tone="info" title={t('sensors.cells.newTitle')}>
          {t('sensors.grantSection.new')}
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
  const { t } = useTranslation()
  if (!sensor.protocol || (!sensor.protocol.deprecated && sensor.protocol.version >= 2)) return null
  return (
    <SensorTag
      tone="warning"
      title={t('sensors.cells.protocolDeprecatedTitle', undefined, {
        version: sensor.protocol.version,
        minVersion: PROTOCOL_V2_SENSOR_VERSION,
        date: PROTOCOL_V1_SUNSET,
      })}
    >
      v{sensor.protocol.version} · {t('sensors.edit.about.deprecated')}
    </SensorTag>
  )
}

const VERSION_TAG: Record<
  SensorVersionStatus,
  { key: string; label: string; tone: 'success' | 'info' | 'destructive' } | null
> = {
  latest: { key: 'sensors.cells.versionTag.latest', label: 'latest', tone: 'success' },
  update_available: { key: 'sensors.cells.versionTag.update', label: 'update', tone: 'info' },
  unsupported: {
    key: 'sensors.cells.versionTag.unsupported',
    label: 'unsupported',
    tone: 'destructive',
  },
  unknown: null,
}

// The SDK release is informational; only a release with a security
// advisory is a warning.
const SDK_TAG: Record<
  SensorSdkStatus,
  { key: string; label: string; tone: 'info' | 'warning' } | null
> = {
  current: null,
  unknown: null,
  outdated: { key: 'sensors.version.sdkOutdated', label: 'SDK outdated', tone: 'info' },
  advisory: {
    key: 'sensors.version.sdkAdvisory',
    label: 'SDK advisory',
    tone: 'warning',
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
  | 'product'
  | 'product_known'
  | 'product_latest_version'
  | 'product_min_version'
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
 * version compares to its product's release line, and a tag when its SDK is
 * outdated (informational) or has a security advisory. The build facts are in
 * the tooltip. The table, the phone cards and the drawer all show the version
 * through this.
 */
export function SensorVersionCell({
  sensor,
  channel,
  showChannelTag = true,
}: {
  sensor: SensorVersionFields
  /** The product catalog and SDK entries from GET /sensors/stats. */
  channel?: ReleaseChannel
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
  const { latest, min } = releaseLineOf(sensor, channel?.products)
  const sdkLatest = channel?.sdkLatest
  const status = sensorVersionStatus(sensor, latest, min)
  const tag = v && showChannelTag ? VERSION_TAG[status] : null
  const title =
    status === 'update_available' && latest
      ? t('sensors.cells.versionAvailable', undefined, { latest })
      : status === 'unsupported' && min
        ? t('sensors.cells.versionTooOld', undefined, { min })
        : undefined
  const sdkStatus = sensorSdkStatus(sensor)
  const sdkTag = SDK_TAG[sdkStatus]
  const sdkTitle =
    sdkStatus === 'advisory'
      ? t('sensors.version.sdkAdvisoryHint', 'This SDK release has a published security advisory')
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
              {t(tag.key, tag.label)}
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
  const { t } = useTranslation()
  if (isOneShotSensor(sensor) || sensor.status !== 'active') {
    return <span className={muted}>—</span>
  }
  const current = sensor.current_jobs ?? 0
  // The capacity dispatch uses: the smallest of the sensor's slots, its
  // operator's cap and the limit set on it.
  const max = sensorCapacity(sensor).effective || 0
  const pct = max > 0 ? Math.min(100, (current / max) * 100) : 0
  return (
    <span className="inline-flex items-center gap-2 tabular-nums" title={capacityLabel(sensor, t)}>
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
  const { t } = useTranslation()
  const ob = sensor.outbox
  if (!ob && sensor.status !== 'active') return <span className={muted}>—</span>
  if (!ob) {
    return (
      <span className={cn('text-sm', muted)} title={t('sensors.cells.outboxUnreported')}>
        {isOneShotSensor(sensor) ? '—' : t('sensors.cells.notReported')}
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
          {t('sensors.cells.queued', undefined, { count: ob.pending_count.toLocaleString() })}
        </span>
      )}
      {lost > 0 && (
        <span className="text-sm tabular-nums text-destructive">
          {t('sensors.cells.lost', undefined, { count: lost.toLocaleString() })}
        </span>
      )}
      {ob.pending_count > 0 && ob.oldest_age_seconds > 0 && (
        <span className={cn('text-xs', muted)}>
          {t('sensors.cells.oldest', undefined, {
            age: formatDurationShort(ob.oldest_age_seconds),
          })}
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
  const { t } = useTranslation()
  return (
    <SensorTag tone="muted" title={t('sensors.cells.legacyKeyHelp', LEGACY_KEY_EXPLANATION)}>
      {t('sensors.cells.legacyKey')}
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
  const { t } = useTranslation()
  const k = keyExpiry(expiresAt, now)
  switch (k.kind) {
    case 'unknown':
      return <span className={muted}>—</span>
    case 'never':
      return (
        <span className={cn('whitespace-nowrap text-sm', muted)}>
          {t('sensors.cells.keyNever')}
        </span>
      )
    case 'expired':
      return (
        <span className="whitespace-nowrap text-sm text-destructive">
          {t('sensors.cells.keyExpired')}
        </span>
      )
    case 'soon':
      return (
        <span className="whitespace-nowrap text-sm text-warning">
          {t(
            k.days === 1 ? 'sensors.cells.keyExpiresIn.one' : 'sensors.cells.keyExpiresIn.other',
            undefined,
            { count: k.days }
          )}
        </span>
      )
    default:
      return (
        <span className={cn('whitespace-nowrap text-sm', muted)}>
          {t(k.days === 1 ? 'sensors.cells.keyIn.one' : 'sensors.cells.keyIn.other', undefined, {
            count: k.days,
          })}
        </span>
      )
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
  const { t } = useTranslation()
  const list = tools ?? []
  if (list.length === 0) {
    return <span className={cn('text-sm', muted)}>{t('sensors.cells.toolsNone')}</span>
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
  { icon: typeof CheckCircle2; className: string; key: string; label: string }
> = {
  ready: {
    icon: CheckCircle2,
    className: 'text-success',
    key: 'sensors.cells.toolInstalled',
    label: 'installed',
  },
  not_installed: {
    icon: AlertTriangle,
    className: 'text-warning',
    key: 'sensors.cells.toolNotInstalled',
    label: 'not installed',
  },
}

/**
 * A sensor's tools for the drawer: one chip per tool with its version and
 * whether it is installed (an icon, and a tag when it is not usable).
 */
export function SensorToolList({ rows }: { rows: SensorToolRow[] }) {
  const { t } = useTranslation()
  return (
    <DetailChipList
      label={t('sensors.cells.tools')}
      chips={rows.map((r) => {
        const st = TOOL_STATUS[r.status]
        return {
          key: r.name,
          data: { tool: r.name, status: r.status },
          icon: st.icon,
          iconClassName: st.className,
          iconLabel: t(st.key, st.label),
          label: r.name,
          muted: r.status !== 'ready' || !!r.excluded,
          meta: (
            <>
              {r.version && <span className={cn('text-xs tabular-nums', muted)}>{r.version}</span>}
              {r.capabilities && r.capabilities.length > 0 && (
                <span
                  className={cn('max-w-48 truncate text-xs', muted)}
                  title={t('sensors.cells.serves', undefined, { list: r.capabilities.join(', ') })}
                  aria-label={t('sensors.cells.serves', undefined, {
                    list: r.capabilities.join(', '),
                  })}
                >
                  {r.capabilities.join(' · ')}
                </span>
              )}
            </>
          ),
          tag:
            r.status === 'not_installed' ? (
              <SensorTag tone="warning">{t('sensors.cells.toolNotInstalled')}</SensorTag>
            ) : r.excluded ? (
              <span title={r.excluded.detail}>
                <SensorTag tone="warning">
                  {r.excluded.reason === 'grant'
                    ? t('sensors.cells.notInGrant')
                    : t('sensors.cells.policyRefuses')}
                </SensorTag>
              </span>
            ) : undefined,
        }
      })}
    />
  )
}
