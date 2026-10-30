import { describe, expect, it } from 'vitest'

import {
  groupsFromUncovered,
  isSkipWarning,
  needsAttention,
  skippedTotal,
  skipReasonKey,
} from '../skip-groups'

describe('skip groups', () => {
  it('names known reasons and folds the rest into other', () => {
    expect(skipReasonKey('unresolved')).toBe('unresolved')
    expect(skipReasonKey('zone_no_sensor')).toBe('zone_no_sensor')
    expect(skipReasonKey('something_new')).toBe('other')
  })

  it('sums the groups and flags only fixable reasons', () => {
    const info = { reason: 'unresolved', tone: 'info' as const, count: 434, targets: [] }
    const warn = { reason: 'zone_no_sensor', tone: 'warning' as const, count: 1, targets: [] }
    expect(skippedTotal([info, warn])).toBe(435)
    expect(needsAttention([info])).toBe(false)
    expect(needsAttention([info, warn])).toBe(true)
  })

  it('groups an older run by reason text, counting the unlisted rest', () => {
    const gone = (n: number) => ({
      target: `g${n}.example.com`,
      reason: 'does not resolve in DNS; fix its DNS record',
    })
    const groups = groupsFromUncovered([gone(1), gone(2)], 434)
    expect(groups).toEqual([
      {
        reason: 'unresolved',
        tone: 'info',
        count: 434,
        targets: ['g1.example.com', 'g2.example.com'],
      },
    ])
    const mixed = groupsFromUncovered(
      [gone(1), { target: '10.0.0.1', reason: 'private address' }],
      10
    )
    expect(mixed.map((g) => [g.reason, g.count])).toEqual([
      ['other', 9],
      ['unresolved', 1],
    ])
    expect(groupsFromUncovered([], 0)).toEqual([])
  })

  it('recognises the server warnings the groups already say', () => {
    expect(isSkipWarning('a.example.com not scanned: does not resolve in DNS')).toBe(true)
    expect(isSkipWarning('12 name(s) left out: no proof they resolved in DNS')).toBe(true)
    expect(isSkipWarning('3 target(s) were skipped: ownership not confirmed')).toBe(true)
    expect(isSkipWarning('2 archived asset(s) in the group(s) were skipped')).toBe(true)
    expect(isSkipWarning('jobs wait in the zone until a sensor is online')).toBe(false)
  })
})
