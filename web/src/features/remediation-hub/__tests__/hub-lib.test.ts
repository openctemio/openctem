/**
 * The pure rules of the remediation hub: deadline status, progress parts,
 * the fix steps of an action key, grouping by asset and the visible window
 * of the long finding list.
 */

import { describe, expect, it } from 'vitest'
import { deadlineStatus, fixSteps, groupByAsset, progressParts } from '../lib/hub'
import { visibleRange } from '../components/virtual-rows'
import type { TaskMember } from '../api/types'

const NOW = Date.parse('2026-10-16T12:00:00Z')

describe('deadlineStatus', () => {
  it('reads overdue, due soon (three days) and on track', () => {
    expect(deadlineStatus(undefined, NOW)).toBe('none')
    expect(deadlineStatus('2026-10-15T00:00:00Z', NOW)).toBe('overdue')
    expect(deadlineStatus('2026-10-18T00:00:00Z', NOW)).toBe('due_soon')
    expect(deadlineStatus('2026-11-01T00:00:00Z', NOW)).toBe('on_track')
    expect(deadlineStatus('not a date', NOW)).toBe('none')
  })
})

describe('progressParts', () => {
  it('splits verified from closed otherwise, then claimed and open', () => {
    const counts = {
      total: 10,
      open: 3,
      in_progress: 1,
      fix_applied: 2,
      closed: 4,
      verified: 3,
      related: 0,
      risk_points: 0,
    }
    expect(progressParts({ counts })).toEqual({
      verified: 3,
      closed: 1,
      claimed: 2,
      open: 4,
      total: 10,
    })
    expect(progressParts({ counts: { ...counts, total: 0 } }).total).toBe(0)
  })
})

describe('fixSteps', () => {
  it('reads an upgrade key and builds the command, restoring a scoped name', () => {
    const s = fixSteps(undefined, 'upgrade:npm:@scope~pkg:1.2.3')
    expect(s.pkg).toBe('@scope/pkg')
    expect(s.target).toBe('1.2.3')
    expect(s.commands[0].code).toContain('@scope/pkg@^1.2.3')
  })
  it('prefers the fix spec and shows only a secret fingerprint prefix', () => {
    expect(
      fixSteps(
        { kind: 'upgrade', ecosystem: 'pypi', package: 'django', target_version: '4.2.30' },
        'x'
      ).commands[0].code
    ).toContain('django>=4.2.30')
    expect(fixSteps(undefined, 'rotate:secret:0123456789abcdef').secretPrefix).toBe('01234567')
    expect(fixSteps(undefined, 'manual:abc').commands).toEqual([])
  })
})

describe('groupByAsset', () => {
  it('keeps asset order and puts findings without an asset last', () => {
    const m = (id: string, asset?: string): TaskMember => ({
      finding_id: id,
      role: 'primary',
      join_source: 'manual',
      title: id,
      severity: 'high',
      status: 'new',
      asset_id: asset,
      asset_name: asset,
      verified: false,
    })
    const g = groupByAsset([m('1'), m('2', 'a'), m('3', 'b'), m('4', 'a')])
    expect(g.map((x) => x.key)).toEqual(['a', 'b', ''])
    expect(g[0].items.map((x) => x.finding_id)).toEqual(['2', '4'])
  })
})

describe('visibleRange', () => {
  it('renders only the rows in view plus the margin', () => {
    expect(visibleRange(0, 440, 44, 10000, 8)).toEqual({ first: 0, last: 18 })
    expect(visibleRange(44000, 440, 44, 10000, 8)).toEqual({ first: 992, last: 1018 })
    expect(visibleRange(0, 440, 44, 5, 8)).toEqual({ first: 0, last: 5 })
  })
})
