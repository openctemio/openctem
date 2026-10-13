import { describe, expect, it } from 'vitest'

import { canFindLiveHosts, effectiveCidrMode } from '../liveness'
import { describeTargetOptions } from '../dynamic-targets'

describe('live hosts first', () => {
  it('a single scanner can always find live hosts; a workflow needs Host discovery', () => {
    expect(canFindLiveHosts('single', undefined)).toBe(true)
    expect(canFindLiveHosts('workflow', undefined)).toBeUndefined()
    expect(
      canFindLiveHosts('workflow', { steps: [{ capabilities: ['scan.ports'] }] as never })
    ).toBe(false)
    expect(
      canFindLiveHosts('workflow', {
        steps: [{ capabilities: ['discover.hosts'] }, { capabilities: ['scan.ports'] }] as never,
      })
    ).toBe(true)
  })

  it('a saved scan without a mode sweeps; a new one defaults to live hosts first', () => {
    expect(effectiveCidrMode(undefined, true)).toBe('sweep')
    expect(effectiveCidrMode(undefined, false)).toBe('liveness')
    expect(effectiveCidrMode('liveness', true)).toBe('liveness')
    expect(effectiveCidrMode('inventory', false)).toBe('inventory')
  })

  it('describes a live hosts first scan as such, not as a sweep', () => {
    expect(describeTargetOptions(['203.0.113.0/24'], { cidr_mode: 'liveness' })).toEqual([
      'Ranges: live hosts first',
    ])
    expect(describeTargetOptions(['203.0.113.0/24'], undefined)).toEqual(['Ranges: swept whole'])
  })
})
