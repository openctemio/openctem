'use client'

import type { SensorGrantSummary } from '@/lib/api/sensor-grant-hooks'
import { AlertTriangle, CheckCircle2, ShieldAlert } from 'lucide-react'

import { useTranslation } from '@/context/i18n-provider'
import { cn } from '@/lib/utils'
import { HealthStatus } from '@/components/ui/health-status'
import { Tag } from '@/components/ui/tag'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { DetailChipList } from '@/features/shared/components/detail-sheet'
import type { Sensor, SensorSdkStatus, SensorVersionStatus } from '@/lib/api/sensor-types'
import type { HealthState } from '@/lib/health-colors'

import { configHealthMeta, configHealthNeedsAttention } from '../lib/config-report'
import { capacityLabel, sensorJobLoad, type SensorToolRow } from '../lib/capabilities'
import { formatDurationShort, keyExpiry, type Tr } from '../lib/format'
import { postureIssues } from '../lib/posture'
import { isOneShotSensor } from '../lib/sensor-state'
import type { ReleaseChannel } from '../lib/fleet'
import {
  normalizeSensorVersion,
  releaseLineOf,
  sensorSdkStatus,
  parsePseudoVersion,
  sensorSdkVersion,
  sensorVersionStatus,
} from '../lib/sensor-version'
import { formatDateTime, formatNumber } from '@/lib/app-locale'

/**
 * Cells shared by the sensor table, the phone cards and the drawer, so one
 * value reads the same everywhere. Theme tokens only.
 */

const muted = 'text-muted-foreground'

/**
 * Small tag next to a value ("update", "unsupported", "Platform", ...). A
 * classification (muted, info) is a neutral Tag; a state that needs a person
 * or is down, or that is fine, is a HealthStatus (warning, destructive,
 * success), so the sensor tags share the one label look.
 */
export function SensorTag({
  tone = 'muted',
  children,
  title,
}: {
  tone?: 'muted' | 'info' | 'warning' | 'destructive' | 'success'
  children: React.ReactNode
  title?: string
}) {
  if (tone === 'warning' || tone === 'destructive' || tone === 'success') {
    const state = tone === 'warning' ? 'warn' : tone === 'destructive' ? 'down' : 'ok'
    return <HealthStatus state={state} label={children} title={title} />
  }
  return <Tag label={children} title={title} />
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
export function SensorPostureTag({
  sensor,
  onOpen,
}: {
  sensor: Pick<Sensor, 'posture'>
  /**
   * Show the posture section (the drawer). The tag is then a button whose
   * tooltip names each gap, so "Unhardened" never stands unexplained.
   */
  onOpen?: () => void
}) {
  const { t } = useTranslation()
  const issues = postureIssues(sensor)
  if (issues.length === 0) return null
  const tag = (
    <SensorTag
      tone="warning"
      title={onOpen ? undefined : issues.map((i) => t(i.fixKey, i.fix)).join('\n')}
    >
      <span data-slot="sensor-posture-tag" className="inline-flex items-center gap-1">
        <ShieldAlert className="h-3 w-3" aria-hidden />
        {t('sensors.posture.tag', 'Unhardened')}
      </span>
    </SensorTag>
  )
  if (!onOpen) return tag
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <button
          type="button"
          onClick={onOpen}
          data-testid="sensor-posture-tag-button"
          aria-label={t(
            issues.length === 1 ? 'sensors.posture.tagOpen.one' : 'sensors.posture.tagOpen.other',
            undefined,
            { count: issues.length }
          )}
          className="rounded-sm focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
        >
          {tag}
        </button>
      </TooltipTrigger>
      <TooltipContent className="max-w-xs">
        <ul className="space-y-0.5">
          {issues.map((i) => (
            <li key={i.reason}>{t(i.labelKey, i.label)}</li>
          ))}
        </ul>
      </TooltipContent>
    </Tooltip>
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
 *
 * `inline` (the list's one-line row): the name and its badges only; the host
 * and the address are the list's Host column (`SensorHostCell`).
 */
export function SensorNameCell({
  sensor,
  grant,
  inline = false,
}: {
  sensor: Sensor
  grant?: SensorGrantSummary
  inline?: boolean
}) {
  const { t } = useTranslation()
  const host = distinctHostname(sensor)
  const ip = sensor.ip_address || null
  const fallback = isOneShotSensor(sensor) ? t('sensors.cells.oneShot') : t('sensors.cells.noHost')
  if (inline) {
    // The name on its own line, its marks on the line under it in one look
    // (the most serious first, the rest as "+N" with every mark in the hover
    // text): a mark never pushes the name aside or sits cut at the cell's edge.
    const flags = sensorFlags(sensor, grant, t)
    return (
      <span className="flex min-w-0 flex-col" data-slot="sensor-name-cell">
        <span
          dir="auto"
          className="block min-w-0 truncate font-medium [unicode-bidi:isolate]"
          data-slot="sensor-name"
          title={sensor.name}
        >
          {sensor.name}
        </span>
        <SensorFlags flags={flags} max={1} />
      </span>
    )
  }
  return (
    <div className="flex min-w-0 flex-col">
      <span className="flex min-w-0 items-center gap-1.5">
        <span className="truncate font-medium" data-slot="sensor-name">
          {sensor.name}
        </span>
        <ProtocolTag sensor={sensor} />
        <ConfigHealthTag health={sensor.config_health} />
        <SensorPostureTag sensor={sensor} />
        {/* A revoked sensor's grant no longer matters. */}
        {sensor.status !== 'revoked' && <SensorGrantTags grant={grant} />}
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
 * The list's Host column, on one line: the host name the sensor reports
 * (when it differs from the sensor's name), else its address; both in the
 * hover text. A sensor that reports neither says so in words.
 */
export function SensorHostCell({ sensor }: { sensor: Sensor }) {
  const { t } = useTranslation()
  const host = distinctHostname(sensor)
  const ip = sensor.ip_address || null
  if (!host && !ip) {
    if (sensor.hostname) {
      return <span className="block truncate text-sm">{sensor.hostname}</span>
    }
    // Nothing reported: a quiet dash, the words in the hover text and for a
    // screen reader (the same words on every such row read as noise).
    const words = isOneShotSensor(sensor) ? t('sensors.cells.oneShot') : t('sensors.cells.noHost')
    return (
      <span className={cn('text-sm', muted)} title={words} data-slot="sensor-host-none">
        <span aria-hidden>—</span>
        <span className="sr-only">{words}</span>
      </span>
    )
  }
  const title = [
    host ? `${t('sensors.cells.hostTitle')}: ${host}` : null,
    ip ? `${t('sensors.cells.ipTitle')}: ${ip}` : null,
  ]
    .filter(Boolean)
    .join('\n')
  return (
    <span className="flex min-w-0 items-baseline gap-2" title={title} data-slot="sensor-host-cell">
      {host && (
        <span className="min-w-16 truncate text-sm" data-slot="sensor-host">
          {host}
        </span>
      )}
      {ip && (
        <span className={cn('shrink-0 text-sm tabular-nums', host && muted)} data-slot="sensor-ip">
          {ip}
        </span>
      )}
    </span>
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
        // What New means, not its name: a newcomer reads "New" as "just added".
        <SensorTag tone="info" title={t('sensors.cells.newTitle')}>
          {t('sensors.cells.passiveOnly')}
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
      v{sensor.protocol.version}, {t('sensors.edit.about.deprecated')}
    </SensorTag>
  )
}

/** One mark on a sensor's name: protocol, setup, posture or grant. */
export interface SensorFlag {
  key: string
  label: string
  /** What it means, for the hover text. */
  title?: string
  tone: 'muted' | 'info' | 'warning' | 'destructive'
}

const FLAG_RANK: Record<SensorFlag['tone'], number> = {
  destructive: 0,
  warning: 1,
  info: 2,
  muted: 3,
}

/**
 * The marks a sensor's name carries, the most serious first: the same set as
 * ProtocolTag, ConfigHealthTag, SensorPostureTag and SensorGrantTags, as data
 * so the list and the phone card draw them in one look.
 */
export function sensorFlags(
  sensor: Pick<Sensor, 'protocol' | 'config_health' | 'posture' | 'status'>,
  grant: SensorGrantSummary | undefined,
  t: Tr
): SensorFlag[] {
  const out: SensorFlag[] = []
  const p = sensor.protocol
  if (p && (p.deprecated || p.version < 2)) {
    out.push({
      key: 'protocol',
      tone: 'warning',
      label: `v${p.version}, ${t('sensors.edit.about.deprecated')}`,
      title: t('sensors.cells.protocolDeprecatedTitle', undefined, {
        version: p.version,
        minVersion: PROTOCOL_V2_SENSOR_VERSION,
        date: PROTOCOL_V1_SUNSET,
      }),
    })
  }
  if (configHealthNeedsAttention(sensor.config_health)) {
    const meta = configHealthMeta(sensor.config_health)
    out.push({
      key: 'setup',
      tone: meta.tone === 'destructive' ? 'destructive' : 'warning',
      label: t(meta.key, meta.label),
      title: t('sensors.setup.healthTitle', 'Setup checks'),
    })
  }
  const issues = postureIssues(sensor)
  if (issues.length > 0) {
    out.push({
      key: 'posture',
      tone: 'warning',
      label: t('sensors.posture.tag', 'Unhardened'),
      title: issues.map((i) => t(i.fixKey, i.fix)).join('\n'),
    })
  }
  // A revoked sensor's grant no longer matters.
  if (grant && sensor.status !== 'revoked') {
    if (grant.legacy_broad) {
      out.push({
        key: 'legacy-broad',
        tone: 'warning',
        label: t('sensors.grantEdit.profile.legacy-broad'),
        title: t('sensors.cells.legacyBroadTitle'),
      })
    }
    if (grant.trust_level === 'new') {
      out.push({
        key: 'passive-only',
        tone: 'info',
        label: t('sensors.cells.passiveOnly'),
        title: t('sensors.cells.newTitle'),
      })
    }
  }
  return out.sort((a, b) => FLAG_RANK[a.tone] - FLAG_RANK[b.tone])
}

// One look for every mark: the state glyph and plain text, no container. A
// mark that needs nobody (Passive only) is the quiet neutral glyph.
const FLAG_STATE: Record<SensorFlag['tone'], HealthState> = {
  destructive: 'down',
  warning: 'warn',
  info: 'off',
  muted: 'off',
}

/**
 * A sensor's marks in one look. `max` (the list's one line under the name):
 * the first marks, then "+N", every mark with its meaning in the hover text
 * and for a screen reader. Without `max` (the phone card) every mark, wrapping.
 */
export function SensorFlags({ flags, max }: { flags: SensorFlag[]; max?: number }) {
  const { t } = useTranslation()
  if (flags.length === 0) return null
  const shown = max ? flags.slice(0, max) : flags
  const rest = flags.length - shown.length
  const all = flags.map((f) => (f.title ? `${f.label}: ${f.title}` : f.label)).join('\n')
  return (
    <span
      data-slot="sensor-flags"
      className={cn(
        'flex min-w-0 items-center gap-x-3 gap-y-1',
        max ? 'flex-nowrap overflow-hidden' : 'flex-wrap'
      )}
      title={rest > 0 ? all : undefined}
    >
      {shown.map((f) => (
        <HealthStatus
          key={f.key}
          state={FLAG_STATE[f.tone]}
          value={f.key}
          label={f.label}
          title={rest > 0 ? all : f.title}
          className="min-w-0 shrink"
        />
      ))}
      {rest > 0 && (
        <span data-slot="sensor-flags-more" className={cn('shrink-0 text-xs tabular-nums', muted)}>
          <span aria-hidden>+{rest}</span>
          <span className="sr-only">
            {t('sensors.cells.moreMarks', '{count} more: {list}', {
              count: rest,
              list: flags
                .slice(shown.length)
                .map((f) => f.label)
                .join(', '),
            })}
          </span>
        </span>
      )}
    </span>
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
  { key: string; label: string; tone: 'info' | 'warning' | 'destructive' } | null
> = {
  current: null,
  unknown: null,
  outdated: { key: 'sensors.version.sdkOutdated', label: 'SDK outdated', tone: 'info' },
  advisory: {
    key: 'sensors.version.sdkAdvisory',
    label: 'SDK advisory',
    tone: 'warning',
  },
  unsupported: {
    key: 'sensors.version.sdkUnsupported',
    label: 'SDK unsupported',
    tone: 'destructive',
  },
}

/**
 * The list's one version signal: unsupported (the release or its SDK) over a
 * security update (an SDK advisory) over an update (a newer release or SDK)
 * over latest. Null when nothing is known.
 */
export function inlineVersionSignal(
  status: SensorVersionStatus,
  sdkStatus: SensorSdkStatus
): { key: string; label: string; state: HealthState; value: string } | null {
  if (status === 'unsupported' || sdkStatus === 'unsupported') {
    return {
      key: 'sensors.cells.versionTag.unsupported',
      label: 'Unsupported',
      state: 'down',
      value: 'unsupported',
    }
  }
  if (sdkStatus === 'advisory') {
    return {
      key: 'sensors.cells.versionTag.securityUpdate',
      label: 'Security update',
      state: 'warn',
      value: 'security_update',
    }
  }
  if (status === 'update_available' || sdkStatus === 'outdated') {
    return {
      key: 'sensors.cells.versionTag.update',
      label: 'Update available',
      state: 'queued',
      value: 'update_available',
    }
  }
  if (status === 'latest') {
    return { key: 'sensors.cells.versionTag.latest', label: 'Latest', state: 'ok', value: 'latest' }
  }
  return null
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
  _locale?: string
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
      lines.push(t('sensors.version.built', 'Built: {value}', { value: formatDateTime(d) }))
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
/**
 * An SDK version as an operator reads it: a release as is, a pseudo-version
 * (a build of an unreleased commit, 40 characters) as "v0.37.1 pre-release".
 * The full string stays in the title and in the drawer's details.
 */
export function sdkLabel(sdk: string, t: Tr): string {
  const pseudo = parsePseudoVersion(sdk)
  return pseudo
    ? t('sensors.version.prerelease', '{version} pre-release', { version: pseudo.base })
    : sdk
}

/** The SDK in the drawer's details: the readable form, then the exact string and commit. */
export function SensorSdkValue({ sensor }: { sensor: SensorVersionFields }) {
  const { t } = useTranslation()
  const sdk = sensorSdkVersion(sensor)
  if (!sdk) return null
  const pseudo = parsePseudoVersion(sdk)
  return (
    <span className="flex min-w-0 flex-col gap-0.5">
      <span className="tabular-nums">{sdkLabel(sdk, t)}</span>
      {pseudo && <span className="font-mono text-xs break-all text-muted-foreground">{sdk}</span>}
    </span>
  )
}

export function SensorVersionCell({
  sensor,
  channel,
  showChannelTag = true,
  showSdk = true,
  inline = false,
}: {
  sensor: SensorVersionFields
  /** The product catalog and SDK entries from GET /sensors/stats. */
  channel?: ReleaseChannel
  /** The latest / update / unsupported tag for the sensor release. */
  showChannelTag?: boolean
  /**
   * The SDK line. The drawer leaves it out (it shows the SDK in its details,
   * see SensorSdkValue) unless the SDK needs attention.
   */
  showSdk?: boolean | 'when-flagged'
  /**
   * The list's one-line row: the release and its channel tag, then the SDK's
   * tag only when the SDK needs attention; the SDK version is in the hover
   * text with the build facts.
   */
  inline?: boolean
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
      : sdkStatus === 'unsupported'
        ? t(
            'sensors.version.sdkUnsupportedHint',
            'This SDK release is older than the oldest this platform supports'
          )
        : sdkStatus === 'outdated'
          ? sdkLatest
            ? t('sensors.version.sdkOutdatedLatest', 'SDK {latest} is available', {
                latest: sdkLatest,
              })
            : t('sensors.version.sdkOutdatedHint', 'A newer SDK is available')
          : undefined
  const build = sensorBuildTooltip(sensor, t, locale)
  const sdkShown = showSdk === 'when-flagged' ? !!sdkTag : showSdk
  if (inline) {
    // One signal at most, the worst of the release and its SDK, so the row
    // never carries two chips cut at the cell's edge; every fact behind it is
    // in the hover text. The signal wraps under the version when the column
    // is narrow (two short lines, never a cut chip).
    const signal = inlineVersionSignal(v ? status : 'unknown', sdk ? sdkStatus : 'unknown')
    return (
      <span
        className="flex min-w-0 flex-wrap items-center gap-x-1.5 gap-y-0.5"
        title={[build, title, sdkTitle].filter(Boolean).join('\n') || undefined}
        data-slot="sensor-version-cell"
      >
        {v ? (
          <span className="whitespace-nowrap text-sm tabular-nums" data-slot="sensor-version">
            {v}
          </span>
        ) : (
          sdk && (
            <span className={cn('min-w-0 truncate text-sm tabular-nums', muted)} title={sdk}>
              {t('sensors.version.sdk', 'SDK')} {sdkLabel(sdk, t)}
            </span>
          )
        )}
        {signal && (
          <HealthStatus
            state={signal.state}
            value={signal.value}
            label={t(signal.key, signal.label)}
            title={[title, sdkTitle].filter(Boolean).join('\n') || undefined}
            className="min-w-0 shrink"
          />
        )}
      </span>
    )
  }
  // Two short lines instead of one long one: the sensor release with its
  // channel tag, then the SDK (smaller, muted) with its warning. min-w-0 and
  // max-w-full keep a long value inside its column (a grid cell or a table
  // cell), never drawn over the next one.
  return (
    <span className="inline-flex max-w-full min-w-0 flex-col gap-0.5" title={build || undefined}>
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
      {sdk && sdkShown && (
        <span className="inline-flex max-w-full min-w-0 flex-wrap items-center gap-x-1.5 gap-y-0.5">
          <span
            className={cn('max-w-full truncate text-xs tabular-nums', muted)}
            data-slot="sdk-version"
            title={sdk}
          >
            {t('sensors.version.sdk', 'SDK')} {sdkLabel(sdk, t)}
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
  // Running against the capacity dispatch uses: the smallest of the
  // sensor's slots, its operator's cap and the limit set on it.
  const jobs = sensorJobLoad(sensor)
  const over = jobs.over > 0
  const pct =
    jobs.capacity > 0
      ? Math.min(100, (jobs.running / Math.max(jobs.capacity, jobs.running)) * 100)
      : 0
  const title = over
    ? `${t('sensors.detail.overCapacity', undefined, { count: jobs.over })}. ${capacityLabel(sensor, t)}`
    : capacityLabel(sensor, t)
  // The bar only while something runs: an empty bar on every idle row is noise.
  return (
    <span className="inline-flex items-center gap-2 tabular-nums" title={title}>
      {jobs.running > 0 && (
        <span
          className="h-1.5 w-11 overflow-hidden rounded-full bg-muted"
          aria-hidden
          data-slot="sensor-jobs-bar"
        >
          <span
            className={cn('block h-full', over ? 'bg-warning' : 'bg-info')}
            style={{ width: `${pct}%` }}
          />
        </span>
      )}
      <span className={cn('text-sm', over ? 'text-warning' : jobs.running === 0 && muted)}>
        {jobs.running}/{jobs.capacity}
      </span>
    </span>
  )
}

/**
 * Results waiting on the sensor (its outbox), as it last reported. `inline`
 * (the list's one-line row): the counts side by side, the age of the oldest
 * in the hover text.
 */
export function SensorOutboxCell({ sensor, inline = false }: { sensor: Sensor; inline?: boolean }) {
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
  const oldest =
    ob.pending_count > 0 && ob.oldest_age_seconds > 0
      ? t('sensors.cells.oldest', undefined, { age: formatDurationShort(ob.oldest_age_seconds) })
      : undefined
  return (
    <span
      className={inline ? 'flex items-baseline gap-2 whitespace-nowrap' : 'flex flex-col'}
      title={inline ? oldest : undefined}
    >
      {ob.pending_count > 0 && (
        <span
          className={cn(
            'text-sm tabular-nums',
            sensor.outbox_warning ? 'text-warning' : 'text-foreground'
          )}
        >
          {t('sensors.cells.queued', undefined, { count: formatNumber(ob.pending_count) })}
        </span>
      )}
      {lost > 0 && (
        <span className="text-sm tabular-nums text-destructive">
          {t('sensors.cells.lost', undefined, { count: formatNumber(lost) })}
        </span>
      )}
      {oldest && !inline && <span className={cn('text-xs', muted)}>{oldest}</span>}
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
  // Up to two short lines in a narrow column: "+N" is never cut away, and
  // every tool is in the hover text.
  return (
    <span
      className={cn('line-clamp-2 text-sm whitespace-normal break-words', muted)}
      title={list.join(', ')}
      data-slot="sensor-tools"
    >
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
 * Why an installed tool gets no scans, in plain words. The API's detail names
 * the grant field that refuses it; the one most sensors hit is the tier
 * ceiling, which a sensor at trust level New holds at passive work (T0).
 */
function ToolExclusionTag({ excluded }: { excluded: NonNullable<SensorToolRow['excluded']> }) {
  const { t } = useTranslation()
  const tier = excluded.reason === 'grant' && /tier_ceiling/.test(excluded.detail ?? '')
  const label = tier
    ? t('sensors.cells.aboveTier')
    : excluded.reason === 'grant'
      ? t('sensors.cells.notInGrant')
      : t('sensors.cells.policyRefuses')
  const help = tier
    ? t('sensors.cells.aboveTierHelp')
    : excluded.reason === 'grant'
      ? t('sensors.cells.notInGrantHelp')
      : t('sensors.cells.policyRefusesHelp')
  return (
    <span title={help}>
      <SensorTag tone="warning">{label}</SensorTag>
      <span className="sr-only">{help}</span>
    </span>
  )
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
                  {r.capabilities.join(', ')}
                </span>
              )}
            </>
          ),
          tag:
            r.status === 'not_installed' ? (
              <SensorTag tone="warning">{t('sensors.cells.toolNotInstalled')}</SensorTag>
            ) : r.excluded ? (
              <ToolExclusionTag excluded={r.excluded} />
            ) : undefined,
        }
      })}
    />
  )
}
