import type { Sensor } from '@/lib/api/sensor-types'
import type { ScanZone } from '@/lib/api/scan-zone-types'

import { dispatchTools, hasReportedTools } from './capabilities'
import { contentCheckSummary, msg } from './content'
import { formatDurationShort, keyExpiry, type Tr } from './format'
import {
  isOneShotSensor,
  sensorState,
  stateIsHeartbeating,
  stateTakesJobs,
  type FleetThresholds,
} from './sensor-state'
import {
  normalizeSensorVersion,
  releaseLineOf,
  sensorProductId,
  sensorSdkStatus,
  sensorSdkVersion,
  sensorVersionStatus,
} from './sensor-version'
import type { ReleaseChannel } from './fleet'
import { sensorProtocolOf } from './fleet'

/**
 * The drawer's health checklist: one line per thing that can be wrong with a
 * sensor, each saying what it found and, when there is one, what to do.
 */
export type HealthCheckStatus = 'ok' | 'warning' | 'critical' | 'info'
export type HealthCheckAction = 'rotate_key' | 'install' | 'edit' | 'zones'

export interface HealthCheck {
  key:
    | 'heartbeat'
    | 'outbox'
    | 'key'
    | 'version'
    | 'sdk'
    | 'tools'
    | 'content'
    | 'zone'
    | 'protocol'
    | 'error'
  label: string
  /** A stable reason where the issue title needs to tell two apart. */
  code?: 'tools_not_reported'
  status: HealthCheckStatus
  text: string
  /** Secondary fact on the right ("up 6d 3h"). */
  aside?: string
  action?: HealthCheckAction
}

export interface HealthCheckContext {
  now: number
  thresholds?: FleetThresholds
  channel: ReleaseChannel
  /** The zones this sensor is assigned to, with the fleet to count them. */
  zones?: Pick<ScanZone, 'id' | 'name' | 'ranges' | 'sensor_ids'>[]
  fleet?: Sensor[]
  /** Protocol v2 release and the v1 sunset (RFC-029). */
  protocolV2Version: string
  protocolV1Sunset: string
}

/** The time since `iso` as a duration ("2m"); null when it is under a second ago or unreadable. */
function duration(iso: string, now: number): string | null {
  const t = new Date(iso).getTime()
  if (Number.isNaN(t) || t >= now - 1000) return null
  return formatDurationShort((now - t) / 1000)
}

function age(iso: string, now: number, tr?: Tr): string {
  const d = duration(iso, now)
  return d === null
    ? msg(tr, 'sensors.time.justNow', 'just now')
    : msg(tr, 'sensors.time.ago', '{duration} ago', { duration: d })
}

/**
 * "Last heartbeat 2m ago, due 1m ago (every 30s)": how late a late or stale
 * sensor is against its own deadline (api RFC-035 §5.6).
 */
function heartbeatDue(
  sensor: Pick<Sensor, 'last_seen_at' | 'heartbeat_due_at' | 'heartbeat_interval_seconds'>,
  now: number,
  tr?: Tr
): string {
  const parts = [
    msg(tr, 'sensors.checks.hbDue.last', 'Last heartbeat {when}', {
      when: sensor.last_seen_at
        ? age(sensor.last_seen_at, now, tr)
        : msg(tr, 'sensors.checks.hbDue.unknown', 'unknown'),
    }),
  ]
  if (sensor.heartbeat_due_at)
    parts.push(
      msg(tr, 'sensors.checks.hbDue.due', 'due {when}', {
        when: age(sensor.heartbeat_due_at, now, tr),
      })
    )
  const every = sensor.heartbeat_interval_seconds
    ? ` ${msg(tr, 'sensors.checks.hbDue.every', '(every {interval})', {
        interval: formatDurationShort(sensor.heartbeat_interval_seconds),
      })}`
    : ''
  return `${parts.join(', ')}${every}.`
}

export function sensorHealthChecks(
  sensor: Sensor,
  ctx: HealthCheckContext,
  tr?: Tr
): HealthCheck[] {
  const { now, thresholds, channel } = ctx
  const state = sensorState(sensor, now, thresholds)
  const oneShot = isOneShotSensor(sensor)
  const checks: HealthCheck[] = []
  const L = {
    heartbeat: msg(tr, 'sensors.checks.label.heartbeat', 'Heartbeat'),
    outbox: msg(tr, 'sensors.checks.label.outbox', 'Outbox'),
    key: msg(tr, 'sensors.checks.label.key', 'API key'),
    version: msg(tr, 'sensors.checks.label.version', 'Version'),
    sdk: msg(tr, 'sensors.checks.label.sdk', 'SDK'),
    protocol: msg(tr, 'sensors.checks.label.protocol', 'Protocol'),
    tools: msg(tr, 'sensors.checks.label.tools', 'Tools'),
    content: msg(tr, 'sensors.checks.label.content', 'Content'),
    zone: msg(tr, 'sensors.checks.label.zone', 'Zone'),
    error: msg(tr, 'sensors.checks.label.error', 'Error'),
  }

  // Heartbeat
  const uptime =
    sensor.uptime_seconds != null && stateIsHeartbeating(state)
      ? msg(tr, 'sensors.checks.hb.uptime', 'up {duration}', {
          duration: formatDurationShort(sensor.uptime_seconds),
        })
      : undefined
  if (state === 'disabled' || state === 'revoked') {
    checks.push({
      key: 'heartbeat',
      label: L.heartbeat,
      status: 'info',
      text:
        state === 'disabled'
          ? msg(
              tr,
              'sensors.checks.hb.disabled',
              'Disabled{reason}. It cannot connect until an admin enables it.',
              { reason: sensor.status_message ? `: ${sensor.status_message}` : '' }
            )
          : msg(
              tr,
              'sensors.checks.hb.revoked',
              'Access revoked. The sensor can no longer connect.'
            ),
    })
  } else if (!sensor.last_seen_at) {
    checks.push({
      key: 'heartbeat',
      label: L.heartbeat,
      status: 'warning',
      text: msg(
        tr,
        'sensors.checks.hb.none',
        'No heartbeat yet. Install the sensor with its key; it shows up here within a minute.'
      ),
      action: 'install',
    })
  } else if (state === 'idle') {
    checks.push({
      key: 'heartbeat',
      label: L.heartbeat,
      status: 'info',
      text: msg(
        tr,
        'sensors.checks.hb.idle',
        'Last run {age}. A CI sensor connects only while it runs.',
        { age: age(sensor.last_seen_at, now, tr) }
      ),
    })
  } else if (state === 'online' || state === 'degraded') {
    checks.push({
      key: 'heartbeat',
      label: L.heartbeat,
      status: 'ok',
      text: age(sensor.last_seen_at, now, tr),
      aside: uptime,
    })
  } else if (state === 'late' || state === 'stale') {
    checks.push({
      key: 'heartbeat',
      label: L.heartbeat,
      status: 'warning',
      text: `${heartbeatDue(sensor, now, tr)} ${
        state === 'late'
          ? msg(tr, 'sensors.checks.hb.lateNote', 'It still takes work.')
          : msg(
              tr,
              'sensors.checks.hb.staleNote',
              'It takes no new work and its queued work goes to other sensors.'
            )
      }`,
      aside: uptime,
    })
  } else {
    checks.push({
      key: 'heartbeat',
      label: L.heartbeat,
      status: 'critical',
      text: msg(
        tr,
        'sensors.checks.hb.offline',
        "No heartbeat for {age}. Check the host, its network path to the platform and the sensor's logs.",
        {
          age: duration(sensor.last_seen_at, now) ?? msg(tr, 'sensors.time.justNow', 'just now'),
        }
      ),
      aside: uptime,
    })
  }

  // Outbox (results waiting on the sensor)
  const ob = sensor.outbox
  if (!oneShot) {
    if (!ob) {
      checks.push({
        key: 'outbox',
        label: L.outbox,
        status: 'info',
        text: msg(
          tr,
          'sensors.checks.outbox.notReported',
          'Not reported. Sensors from v0.4.0 report results waiting to upload.'
        ),
      })
    } else {
      const lost = ob.dead_letter_count + ob.evicted_count
      const reported = msg(tr, 'sensors.checks.outbox.reported', 'reported {age}', {
        age: age(ob.reported_at, now, tr),
      })
      if (lost > 0) {
        checks.push({
          key: 'outbox',
          label: L.outbox,
          status: 'critical',
          text:
            ob.dead_letter_count > 0
              ? msg(
                  tr,
                  'sensors.checks.outbox.dead',
                  '{count} results were refused for good. Run openctemio-sensor -outbox-status on the host to see why.',
                  { count: ob.dead_letter_count }
                )
              : msg(
                  tr,
                  'sensors.checks.outbox.evicted',
                  "{count} results were dropped at the outbox's size or age limit.",
                  { count: ob.evicted_count }
                ),
          aside: reported,
        })
      } else if (ob.pending_count > 0) {
        const waiting = msg(
          tr,
          'sensors.checks.outbox.pending',
          '{count} results waiting to upload',
          { count: ob.pending_count.toLocaleString() }
        )
        const oldest = ob.oldest_age_seconds
          ? msg(tr, 'sensors.checks.outbox.oldest', ', the oldest for {age}', {
              age: formatDurationShort(ob.oldest_age_seconds),
            })
          : ''
        const warn = sensor.outbox_warning
          ? ` ${msg(tr, 'sensors.checks.outbox.warn', 'Check that the sensor can reach the platform URL.')}`
          : ''
        checks.push({
          key: 'outbox',
          label: L.outbox,
          status: sensor.outbox_warning ? 'warning' : 'ok',
          text: `${waiting}${oldest}.${warn}`,
          aside: reported,
        })
      } else {
        checks.push({
          key: 'outbox',
          label: L.outbox,
          status: 'ok',
          text: msg(tr, 'sensors.checks.outbox.empty', 'Empty, nothing waiting to upload'),
          aside: reported,
        })
      }
    }
  }

  // API key
  const k = keyExpiry(sensor.key_expires_at, now)
  if (k.kind === 'expired') {
    checks.push({
      key: 'key',
      label: L.key,
      status: 'critical',
      text: msg(
        tr,
        'sensors.checks.key.expired',
        'Expired: the sensor cannot connect. Rotate the key and update the sensor.'
      ),
      action: 'rotate_key',
    })
  } else if (k.kind === 'soon') {
    checks.push({
      key: 'key',
      label: L.key,
      status: 'warning',
      text:
        k.days === 1
          ? msg(
              tr,
              'sensors.checks.key.soon.one',
              "Expires in {days} day. The sensor renews it on its own; rotate it now if it can't.",
              { days: k.days }
            )
          : msg(
              tr,
              'sensors.checks.key.soon.other',
              "Expires in {days} days. The sensor renews it on its own; rotate it now if it can't.",
              { days: k.days }
            ),
      action: 'rotate_key',
    })
  } else if (k.kind === 'later') {
    checks.push({
      key: 'key',
      label: L.key,
      status: 'ok',
      text: msg(tr, 'sensors.checks.key.later', 'Expires in {days} days', { days: k.days }),
    })
  } else if (k.kind === 'never') {
    checks.push({
      key: 'key',
      label: L.key,
      status: 'ok',
      text: msg(tr, 'sensors.checks.key.never', 'Never expires'),
    })
  }

  // Version
  const v = normalizeSensorVersion(sensor.version)
  const line = releaseLineOf(sensor, channel.products)
  const vs = sensorVersionStatus(sensor, line.latest, line.min)
  checks.push(
    !v
      ? {
          key: 'version',
          label: L.version,
          status: 'info',
          text: msg(tr, 'sensors.checks.version.notReported', 'Not reported yet'),
        }
      : vs === 'unsupported'
        ? {
            key: 'version',
            label: L.version,
            status: 'critical',
            text: msg(
              tr,
              'sensors.checks.version.unsupported',
              '{version}, older than the minimum supported {min}. Upgrade the sensor.',
              { version: v, min: line.min ?? '' }
            ),
            action: 'install',
          }
        : vs === 'update_available'
          ? {
              key: 'version',
              label: L.version,
              status: 'info',
              text: msg(
                tr,
                'sensors.checks.version.available',
                '{version}; {latest} is available.',
                { version: v, latest: line.latest ?? '' }
              ),
              action: 'install',
            }
          : vs === 'latest'
            ? {
                key: 'version',
                label: L.version,
                status: 'ok',
                text: latestIsBuiltIn(sensor, channel)
                  ? msg(
                      tr,
                      'sensors.checks.version.latestBuiltIn',
                      '{version}, the newest release this platform knows. Newer releases may exist: the platform has no current release information.',
                      { version: v }
                    )
                  : msg(tr, 'sensors.checks.version.latest', '{version}, the latest release', {
                      version: v,
                    }),
              }
            : { key: 'version', label: L.version, status: 'info', text: v }
  )

  // SDK, only when it needs attention (the version line covers the rest)
  const sdk = sensorSdkVersion(sensor)
  const sdkStatus = sensorSdkStatus(sensor)
  const sdkReason = sensor.health_reasons?.find((r) => r.code === 'sdk_advisory')
  const sdkName = sdk ?? msg(tr, 'sensors.checks.sdk.the', 'The SDK')
  if (sdkStatus === 'advisory' || sdkReason) {
    checks.push({
      key: 'sdk',
      label: L.sdk,
      status: 'warning',
      text: msg(
        tr,
        'sensors.checks.sdk.advisory',
        '{sdk} has a published security advisory. Upgrade the sensor to a build with a fixed SDK.',
        { sdk: sdkName }
      ),
      action: 'install',
    })
  } else if (sdkStatus === 'outdated') {
    checks.push({
      key: 'sdk',
      label: L.sdk,
      status: 'info',
      text: msg(tr, 'sensors.checks.sdk.outdated', '{sdk} is outdated{latest}.', {
        sdk: sdkName,
        latest: channel.sdkLatest
          ? msg(tr, 'sensors.checks.sdk.latest', '; {version} is available', {
              version: channel.sdkLatest,
            })
          : '',
      }),
      action: 'install',
    })
  }

  // Protocol (RFC-029), once the API reports it
  if (sensor.protocol) {
    const p = sensorProtocolOf(sensor)
    checks.push(
      p === 'v1'
        ? {
            key: 'protocol',
            label: L.protocol,
            status: 'warning',
            text: msg(
              tr,
              'sensors.checks.protocol.v1',
              'v1, deprecated. Upgrade the sensor to {version} or later before {date}.',
              { version: ctx.protocolV2Version, date: ctx.protocolV1Sunset }
            ),
            action: 'install',
          }
        : { key: 'protocol', label: L.protocol, status: 'ok', text: 'v2' }
    )
  }

  // Tools: what dispatch uses (the installed tools the sensor reports)
  const tools = dispatchTools(sensor)
  const reported = hasReportedTools(sensor)
  const scans = sensor.type !== 'collector'
  if (tools.length > 0) {
    checks.push({ key: 'tools', label: L.tools, status: 'ok', text: tools.join(', ') })
  } else if (scans && !oneShot) {
    checks.push(
      reported
        ? {
            key: 'tools',
            label: L.tools,
            status: 'warning',
            text: msg(
              tr,
              'sensors.checks.tools.none',
              'The sensor reports no installed tool, so no scan can be dispatched to it.'
            ),
          }
        : {
            key: 'tools',
            label: L.tools,
            code: 'tools_not_reported',
            status: 'warning',
            text: msg(
              tr,
              'sensors.checks.tools.notReported',
              'The sensor has not reported its tools, so no scan can be dispatched to it. Upgrade it to a build that reports them.'
            ),
            action: 'install',
          }
    )
  }

  // Scanner content (RFC-031), once the sensor reports it
  const content = contentCheckSummary(sensor, now, tr)
  if (content) checks.push({ key: 'content', label: L.content, ...content })

  // Zone
  if (ctx.zones) {
    const mine = ctx.zones.filter((z) => z.sensor_ids.includes(sensor.id))
    if (mine.length === 0) {
      checks.push({
        key: 'zone',
        label: L.zone,
        status: 'info',
        text: ctx.zones.length
          ? msg(tr, 'sensors.checks.zone.none', 'No zone: it takes jobs no zone claims.')
          : msg(tr, 'sensors.checks.zone.noZones', 'No scan zones in this organization.'),
        action: ctx.zones.length ? 'zones' : undefined,
      })
    } else {
      const fleet = ctx.fleet ?? []
      const parts = mine.map((z) => {
        const members = fleet.filter((s) => z.sensor_ids.includes(s.id))
        const online = members.filter((s) => {
          const st = sensorState(s, now, thresholds)
          return stateTakesJobs(st)
        }).length
        const ranges = z.ranges.length ? ` · ${z.ranges.slice(0, 2).join(', ')}` : ''
        return msg(tr, 'sensors.checks.zone.entry', '{name}{ranges} ({online} of {total} online)', {
          name: z.name,
          ranges,
          online,
          total: members.length,
        })
      })
      checks.push({ key: 'zone', label: L.zone, status: 'ok', text: parts.join('; ') })
    }
  }

  // An error the sensor reported
  const err = sensor.health_reasons?.find((r) => r.code === 'error_reported')
  if (err) checks.push({ key: 'error', label: L.error, status: 'warning', text: err.message })

  return checks
}

/**
 * True when the sensor's product line comes from the version built into the
 * platform (no release feed applied), so "latest" may be out of date.
 */
function latestIsBuiltIn(sensor: Sensor, channel: ReleaseChannel): boolean {
  const id = sensorProductId(sensor)
  return channel.products?.find((p) => p.id === id)?.latest_source === 'built_in'
}
