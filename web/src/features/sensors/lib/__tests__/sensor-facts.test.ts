import { describe, expect, it } from 'vitest'

import type { Sensor } from '@/lib/api/sensor-types'
import { TEST_SENSOR_KEY_PREFIX } from '@/test/sensor-keys'

import {
  EMPTY_FLEET_FILTERS,
  activeFilterCount,
  filterSensors,
  isCleanupCandidate,
  summarizeFleet,
} from '../fleet'
import { sensorFacts, sensorReason, VERSION_FACT_KEYS } from '../sensor-facts'

const NOW = new Date('2026-10-02T12:00:00Z').getTime()
const ago = (s: number) => new Date(NOW - s * 1000).toISOString()
const DAY = 86400
const t = (key: string, fallback?: string, vars?: Record<string, string | number>) =>
  `${key}${vars ? JSON.stringify(vars) : ''}` || fallback || ''
const channel = { products: [], sdkLatest: null, sdkAdvisories: [] }

function sensor(over: Partial<Sensor> = {}): Sensor {
  return {
    id: 's1',
    tenant_id: 't',
    name: 'sensor-1',
    type: 'worker',
    capabilities: [],
    execution_mode: 'daemon',
    status: 'active',
    health: 'online',
    api_key_prefix: TEST_SENSOR_KEY_PREFIX,
    cpu_percent: 0,
    memory_percent: 0,
    max_concurrent_jobs: 5,
    current_jobs: 0,
    labels: {},
    config: {},
    metadata: {},
    total_findings: 0,
    total_scans: 0,
    error_count: 0,
    created_at: ago(2 * DAY),
    updated_at: ago(5),
    last_seen_at: ago(5),
    effective: { tools: ['nuclei'], capabilities: [], max_concurrent_jobs: 5 },
    ...over,
  }
}

const facts = (s: Sensor) => sensorFacts(s, { now: NOW, channel }, t)

describe('sensorFacts', () => {
  it('gives a healthy sensor no reason', () => {
    expect(sensorReason(facts(sensor()))).toBeUndefined()
  })

  it('names a missing required local policy first: every network job is refused', () => {
    const s = sensor({
      local_policy: { state: 'absent', required: true, kill_switch: false },
      outbox: {
        pending_count: 3,
        oldest_age_seconds: 60,
        pending_bytes: 0,
        dead_letter_count: 0,
        evicted_count: 0,
        reported_at: ago(5),
      },
    })
    expect(sensorReason(facts(s))).toMatchObject({ key: 'policy', tone: 'destructive' })
  })

  it('does not flag a sensor that runs without a policy it does not require', () => {
    const s = sensor({ local_policy: { state: 'absent', required: false, kill_switch: false } })
    expect(facts(s).map((f) => f.key)).not.toContain('policy')
  })

  it('flags an identity used from two hosts', () => {
    expect(sensorReason(facts(sensor({ identity_cloned_at: ago(60) })))).toMatchObject({
      key: 'cloned',
      tone: 'destructive',
    })
  })

  it('says a sensor added days ago never connected, but not one added minutes ago', () => {
    const old = sensor({ last_seen_at: undefined, created_at: ago(3 * DAY) })
    expect(sensorReason(facts(old))).toMatchObject({ key: 'never', tone: 'warning' })
    const fresh = sensor({ last_seen_at: undefined, created_at: ago(600) })
    expect(sensorReason(facts(fresh))).toBeUndefined()
  })

  it('skips what the Version column already says', () => {
    const s = sensor({ version: 'v0.1.0', version_status: 'unsupported' })
    expect(sensorReason(facts(s))?.key).toBe('unsupported')
    expect(sensorReason(facts(s), VERSION_FACT_KEYS)).toBeUndefined()
  })

  it('lists nothing about work for a disabled sensor', () => {
    const keys = facts(sensor({ status: 'disabled' })).map((f) => f.key)
    expect(keys).not.toContain('seen')
    expect(keys).not.toContain('jobs')
  })
})

describe('isCleanupCandidate', () => {
  it('picks a sensor never connected for over a day and one offline for over a week', () => {
    expect(
      isCleanupCandidate(sensor({ last_seen_at: undefined, created_at: ago(2 * DAY) }), NOW)
    ).toBe(true)
    expect(isCleanupCandidate(sensor({ last_seen_at: ago(8 * DAY), health: 'offline' }), NOW)).toBe(
      true
    )
  })

  it('leaves recent, online, disabled and revoked sensors alone', () => {
    expect(
      isCleanupCandidate(sensor({ last_seen_at: undefined, created_at: ago(3600) }), NOW)
    ).toBe(false)
    expect(isCleanupCandidate(sensor({ last_seen_at: ago(2 * DAY), health: 'offline' }), NOW)).toBe(
      false
    )
    expect(isCleanupCandidate(sensor(), NOW)).toBe(false)
    expect(isCleanupCandidate(sensor({ status: 'disabled', last_seen_at: undefined }), NOW)).toBe(
      false
    )
    expect(
      isCleanupCandidate(sensor({ status: 'revoked', last_seen_at: ago(30 * DAY) }), NOW)
    ).toBe(false)
  })

  it('is a filter and a count on the fleet', () => {
    const fleet = [
      sensor({ id: 'a' }),
      sensor({ id: 'b', last_seen_at: undefined, created_at: ago(2 * DAY) }),
      sensor({ id: 'c', last_seen_at: ago(9 * DAY), health: 'offline' }),
    ]
    const f = { ...EMPTY_FLEET_FILTERS, cleanup: true }
    expect(filterSensors(fleet, f, NOW, undefined, channel).map((s) => s.id)).toEqual(['b', 'c'])
    expect(activeFilterCount(f)).toBe(1)
    expect(summarizeFleet(fleet, NOW, undefined, channel).cleanup).toBe(2)
  })
})
