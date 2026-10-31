import type { Sensor } from '@/lib/api/sensor-types'

import { sensorCapacity } from './capabilities'
import { contentStateLabel, worstContentState } from './content'
import { agoShort, formatDurationShort, keyExpiry, type Tr } from './format'
import {
  ATTENTION_WORDS,
  isCleanupCandidate,
  sensorAttentionKinds,
  sensorPolicyOf,
  versionStatusIn,
  type ReleaseChannel,
} from './fleet'
import {
  isOneShotSensor,
  sensorState,
  sensorStoppedClaiming,
  type FleetThresholds,
} from './sensor-state'
import { normalizeSensorVersion, sensorSdkStatus, sensorSdkVersion } from './sensor-version'

/** One short fact about a sensor; a tone marks one that needs attention. */
export interface SensorFact {
  key: string
  text: string
  tone?: 'warning' | 'destructive'
}

export interface SensorFactContext {
  now: number
  thresholds?: FleetThresholds
  channel: ReleaseChannel
}

/**
 * The facts a list row shows about a sensor, the ones that need attention
 * first: what stops it taking work, results waiting, version, key, content.
 * One source for the phone card (every fact) and the table's Status column
 * (the first fact with a tone: the reason in plain words), so the two never
 * word a problem differently.
 */
export function sensorFacts(sensor: Sensor, ctx: SensorFactContext, t: Tr): SensorFact[] {
  const { now, thresholds, channel } = ctx
  const state = sensorState(sensor, now, thresholds)
  const live = state !== 'disabled' && state !== 'revoked'
  const facts: SensorFact[] = []

  // Why a heartbeating sensor takes no work comes first: "Degraded" alone
  // does not say what to fix.
  if (sensor.identity_cloned_at && live) {
    facts.push({ key: 'cloned', text: t('sensors.facts.identityCloned'), tone: 'destructive' })
  }
  if (sensorStoppedClaiming(sensor) && live) {
    facts.push({ key: 'storage', text: t('sensors.mobile.storageFull'), tone: 'destructive' })
  }
  if (live && sensorPolicyOf(sensor) === 'absent' && sensor.local_policy?.required) {
    facts.push({ key: 'policy', text: t('sensors.facts.noLocalPolicy'), tone: 'destructive' })
  }
  if (live && sensor.local_policy?.kill_switch) {
    facts.push({ key: 'kill', text: t('sensors.facts.paused'), tone: 'warning' })
  }

  const ob = sensor.outbox
  if (ob && ob.pending_count > 0) {
    facts.push({
      key: 'outbox',
      text: `${t('sensors.mobile.resultsWaiting', undefined, { count: ob.pending_count.toLocaleString() })}${ob.oldest_age_seconds ? `, ${formatDurationShort(ob.oldest_age_seconds)}` : ''}`,
      tone: sensor.outbox_warning ? 'warning' : undefined,
    })
  }
  // A sensor added a while ago that never connected: most likely an install
  // that never happened, a candidate to remove.
  if (state === 'never_connected' && isCleanupCandidate(sensor, now, thresholds)) {
    facts.push({
      key: 'never',
      text: t('sensors.facts.neverConnectedSince', undefined, {
        age: agoShort(sensor.created_at, now, t),
      }),
      tone: 'warning',
    })
  }
  if (sensor.last_seen_at && live) {
    facts.push({ key: 'seen', text: agoShort(sensor.last_seen_at, now, t) })
  }
  if (!isOneShotSensor(sensor) && live) {
    facts.push({
      key: 'jobs',
      text: t('sensors.mobile.jobs', undefined, {
        current: sensor.current_jobs ?? 0,
        max: sensorCapacity(sensor).effective,
      }),
    })
  }
  const v = normalizeSensorVersion(sensor.version)
  const vs = versionStatusIn(sensor, channel)
  if (v && vs === 'update_available')
    facts.push({
      key: 'update',
      text: t('sensors.mobile.updateAvailable', undefined, { version: v }),
    })
  if (v && vs === 'unsupported')
    facts.push({
      key: 'unsupported',
      text: t('sensors.mobile.unsupported', undefined, { version: v }),
      tone: 'destructive',
    })
  // The SDK only when it needs attention, worded like the table's tag.
  const sdk = sensorSdkVersion(sensor)
  const sdkStatus = sensorSdkStatus(sensor)
  if (sdkStatus === 'advisory') {
    facts.push({
      key: 'sdk',
      text: sdk
        ? t('sensors.version.sdkAdvisoryFact', 'SDK {version} has an advisory', { version: sdk })
        : t('sensors.version.sdkAdvisory', 'SDK advisory'),
      tone: 'warning',
    })
  }
  if (sdkStatus === 'unsupported') {
    facts.push({
      key: 'sdk',
      text: sdk
        ? t('sensors.version.sdkUnsupportedFact', 'SDK {version} is unsupported', {
            version: sdk,
          })
        : t('sensors.version.sdkUnsupported', 'SDK unsupported'),
      tone: 'destructive',
    })
  }
  const k = keyExpiry(sensor.key_expires_at, now)
  if (k.kind === 'soon')
    facts.push({
      key: 'key',
      text: t('sensors.mobile.keyExpires', undefined, { days: k.days }),
      tone: 'warning',
    })
  if (k.kind === 'expired')
    facts.push({ key: 'key', text: t('sensors.mobile.keyExpired'), tone: 'destructive' })
  if (sensor.legacy_key) facts.push({ key: 'legacy', text: t('sensors.mobile.legacyKey') })
  const content = worstContentState(sensor.content)
  if (content === 'failed' || content === 'stale') {
    facts.push({
      key: 'content',
      text: t('sensors.mobile.content', undefined, {
        state: contentStateLabel(content, t).toLowerCase(),
      }),
      tone: content === 'failed' ? 'destructive' : 'warning',
    })
  }

  // A degraded sensor always says why, even for a problem the facts above do
  // not word (a setup check, a slow heartbeat loop): the fleet's words for it.
  if (state === 'degraded' && !facts.some((f) => f.tone)) {
    const kinds = sensorAttentionKinds(sensor, channel, state)
    if (kinds.length > 0) {
      facts.unshift({
        key: 'attention',
        text: kinds.map((kind) => t(ATTENTION_WORDS[kind])).join(', '),
        tone: 'warning',
      })
    }
  }
  return facts
}

/** Facts the table's Version column already shows (release and SDK tags). */
export const VERSION_FACT_KEYS = ['update', 'unsupported', 'sdk']

/**
 * The reason a row needs attention, in plain words: its first toned fact,
 * skipping the ones another visible column already says (`skip`).
 */
export function sensorReason(
  facts: SensorFact[],
  skip: readonly string[] = []
): SensorFact | undefined {
  return facts.find((f) => f.tone && !skip.includes(f.key))
}
