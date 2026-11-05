import { describe, expect, it } from 'vitest'

import { canFindLiveHosts, effectiveCidrMode } from '../liveness'
import { apiTargetOptions, describeTargetOptions } from '../dynamic-targets'
import { enTranslate } from '../translate'

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

  // The API's rule on save (applyCIDRMode): a new scan without a mode gets
  // live hosts first only when its scan can run it, and is swept otherwise.
  it('a new scan whose workflow cannot find live hosts sweeps, as the API saves it', () => {
    expect(effectiveCidrMode(undefined, false, false)).toBe('sweep')
    expect(effectiveCidrMode(undefined, false, true)).toBe('liveness')
    // Still loading: the API decides on save; the console shows its usual answer.
    expect(effectiveCidrMode(undefined, false, undefined)).toBe('liveness')
    expect(effectiveCidrMode('liveness', false, false)).toBe('liveness')
    expect(effectiveCidrMode(undefined, true, true)).toBe('sweep')
  })

  it('the summary of a new scan says the mode it runs, not a sweep', () => {
    const unset = effectiveCidrMode(undefined, false, true)
    expect(describeTargetOptions(['203.0.113.0/24'], undefined, enTranslate, unset)).toEqual([
      'Ranges: live hosts first',
    ])
    expect(
      describeTargetOptions(
        ['203.0.113.0/24'],
        undefined,
        enTranslate,
        effectiveCidrMode(undefined, false, false)
      )
    ).toEqual(['Ranges: swept whole'])
  })

  // Without a choice nothing is sent: the API applies the same rule.
  it('sends no mode until a person chooses one', () => {
    expect(apiTargetOptions({})).toBeUndefined()
    expect(apiTargetOptions({ cidr_mode: 'sweep' })).toEqual({ cidr_mode: 'sweep' })
  })

  it('describes a live hosts first scan as such, not as a sweep', () => {
    expect(describeTargetOptions(['203.0.113.0/24'], { cidr_mode: 'liveness' })).toEqual([
      'Ranges: live hosts first',
    ])
    expect(describeTargetOptions(['203.0.113.0/24'], undefined)).toEqual(['Ranges: swept whole'])
  })
})
