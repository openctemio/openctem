import { describe, expect, it } from 'vitest'

import type { SensorPosture } from '@/lib/api/sensor-types'

import {
  isUnhardened,
  postureIssues,
  postureLocalPolicy,
  postureNetwork,
  posturePlatformPin,
} from '../posture'

const posture = (p: Partial<SensorPosture>): { posture: SensorPosture } => ({
  posture: {
    local_policy: 'unknown',
    platform_pin: 'unknown',
    network_enforced: null,
    unhardened: [],
    ...p,
  },
})

describe('postureIssues', () => {
  it('maps every reason to its fix, in the API order', () => {
    const issues = postureIssues(
      posture({ unhardened: ['pin_none', 'policy_none', 'network_unenforced', 'bearer_key'] })
    )
    expect(issues.map((i) => i.reason)).toEqual([
      'pin_none',
      'policy_none',
      'network_unenforced',
      'bearer_key',
    ])
    expect(issues[0].fix).toBe('Pin the platform CA with SENSOR_CA_FINGERPRINT.')
    expect(issues[1].fix).toBe(
      'Install a local policy (the Local policy tab of the install commands).'
    )
    expect(issues[2].fix).toContain('SENSOR_SANDBOX_NETWORK=required and the seccomp profile')
  })

  it('skips unknown and repeated reasons, and an API without the posture', () => {
    expect(
      postureIssues(posture({ unhardened: ['from_the_future', 'pin_none', 'pin_none'] }))
    ).toHaveLength(1)
    expect(postureIssues({})).toEqual([])
    expect(isUnhardened({})).toBe(false)
    expect(isUnhardened(posture({}))).toBe(false)
    expect(isUnhardened(posture({ unhardened: ['bearer_key'] }))).toBe(true)
  })
})

describe('posture values', () => {
  it('labels the local policy, the pin and the network', () => {
    expect(postureLocalPolicy(posture({ local_policy: 'enforced' })).tone).toBe('ok')
    expect(postureLocalPolicy(posture({ local_policy: 'absent_required' })).label).toBe(
      'Missing (network jobs refused)'
    )
    expect(postureLocalPolicy(posture({ local_policy: 'absent_legacy' })).tone).toBe('warn')
    expect(postureLocalPolicy({}).label).toBe('Not reported')
    expect(posturePlatformPin(posture({ platform_pin: 'none' })).tone).toBe('warn')
    expect(posturePlatformPin(posture({ platform_pin: 'ca_file' })).tone).toBe('ok')
    expect(posturePlatformPin(posture({ platform_pin: 'unknown' })).tone).toBe('muted')
    expect(postureNetwork(posture({ network_enforced: false })).label).toBe('Not confined')
    expect(postureNetwork(posture({ network_enforced: true })).tone).toBe('ok')
    expect(postureNetwork(posture({ network_enforced: null })).tone).toBe('muted')
  })
})
