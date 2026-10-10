import { describe, expect, it } from 'vitest'
import {
  activeConditions,
  addCondition,
  conditionLabel,
  moveRule,
  newRule,
  removeCondition,
  validClock,
} from '../approval-rules'
import type { ScanApprovalRule } from '@/lib/api/scan-approval-hooks'

const t = (_k: string, fallback?: string, vars?: Record<string, string | number>) => {
  let s = fallback ?? _k
  for (const [k, v] of Object.entries(vars ?? {})) s = s.split(`{${k}}`).join(String(v))
  return s
}

describe('approval rule helpers', () => {
  it('adds, lists and removes conditions in editor order', () => {
    let c = addCondition({}, 'hours')
    c = addCondition(c, 'min_intensity')
    c = addCondition(c, 'origins')
    expect(activeConditions(c)).toEqual(['min_intensity', 'origins', 'hours'])
    expect(addCondition(c, 'min_intensity')).toBe(c)
    c = removeCondition(c, 'origins')
    expect(activeConditions(c)).toEqual(['min_intensity', 'hours'])
    expect(activeConditions({ crown_jewel: false, targets_over: 0 })).toEqual([])
  })

  it('labels chips with names for ids and summarises long lists', () => {
    expect(conditionLabel(t, { min_intensity: 'active' }, 'min_intensity')).toBe(
      'Intensity active or above'
    )
    expect(conditionLabel(t, { tools: ['a', 'b', 'c', 'd', 'e'] }, 'tools')).toBe(
      'Tools: a, b, c +2'
    )
    expect(
      conditionLabel(t, { requester_group_ids: ['g-1111111'] }, 'requester_group_ids', {
        'g-1111111': 'Ops',
      })
    ).toBe('Requester in: Ops')
    expect(conditionLabel(t, { origins: ['api_key', 'ci'] }, 'origins')).toBe(
      'Through: api_key, ci'
    )
    expect(
      conditionLabel(
        t,
        {
          hours: {
            match: 'outside',
            windows: [{ days: ['mon', 'fri'], start: '09:00', end: '18:00' }],
          },
        },
        'hours'
      )
    ).toBe('Outside mon fri 09:00–18:00')
  })

  it('moves a rule and ignores moves out of range', () => {
    const rules = ['a', 'b', 'c'].map((name) => ({
      ...newRule(),
      id: name,
      name,
    })) as ScanApprovalRule[]
    expect(moveRule(rules, 2, 0).map((r) => r.name)).toEqual(['c', 'a', 'b'])
    expect(moveRule(rules, 0, 5)).toBe(rules)
    expect(moveRule(rules, 1, 1)).toBe(rules)
  })

  it('checks clock times', () => {
    expect(validClock('09:00')).toBe(true)
    expect(validClock('24:00')).toBe(false)
    expect(validClock('24:00', true)).toBe(true)
    expect(validClock('9:00')).toBe(false)
    expect(validClock('12:60')).toBe(false)
  })
})
