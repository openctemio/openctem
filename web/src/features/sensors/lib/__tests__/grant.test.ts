import { describe, expect, it } from 'vitest'

import { grantUpdateRequest, type SensorGrant } from '@/lib/api/sensor-grant-hooks'

import { formatGrantList, parseListInput, profileLabel, widenedDimensions } from '../grant'

const base: SensorGrant = {
  sensor_id: 's1',
  profile: 'easm-external',
  legacy_broad: false,
  trust_level: 'new',
  job_types: ['scan'],
  zone_ids: null,
  tools: ['nuclei'],
  capabilities: null,
  tier_ceiling: 1,
  target_network: 'public',
  target_cidrs: ['10.0.0.0/8'],
  target_domains: null,
  allow_credentials: false,
  allow_push_ingest: false,
  remote_actions: [],
  version: 1,
}

describe('grant helpers', () => {
  it('reads null as Any and [] as None', () => {
    expect(formatGrantList(null)).toBe('Any')
    expect(formatGrantList([])).toBe('None')
    expect(formatGrantList(['a', 'b'])).toBe('a, b')
  })

  it('narrowing is not widening', () => {
    expect(widenedDimensions(base, grantUpdateRequest(base))).toEqual([])
    expect(
      widenedDimensions(
        base,
        grantUpdateRequest(base, { tools: [], tier_ceiling: 0, target_network: 'none' })
      )
    ).toEqual([])
  })

  it('names every widened dimension', () => {
    const next = grantUpdateRequest(base, {
      trust_level: 'trusted',
      tools: null,
      job_types: ['scan', 'validate'],
      tier_ceiling: 2,
      target_network: 'any',
      target_cidrs: null,
      allow_credentials: true,
      allow_push_ingest: true,
      remote_actions: ['update'],
    })
    expect(widenedDimensions(base, next)).toEqual([
      'trust level',
      'job types',
      'tools',
      'tier ceiling',
      'target network',
      'target scope',
      'credentials',
      'push ingest',
      'remote actions',
    ])
  })

  it('parses lists and labels profiles', () => {
    expect(parseListInput(' b, a\na ')).toEqual(['a', 'b'])
    expect(profileLabel('collector:github')).toBe('Collector (github)')
    expect(profileLabel('legacy-broad')).toBe('Legacy broad grant')
  })
})
