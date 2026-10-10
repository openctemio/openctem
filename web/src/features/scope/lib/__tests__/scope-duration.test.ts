/**
 * How long a scope entry lasts (RFC-054 §12.4): the default is the longest
 * value the policy allows and never a forbidden one; Permanent is offered
 * only when allowed (forbidden for T2 unless an owner allows it, hidden for
 * a member request).
 */
import { describe, expect, it } from 'vitest'
import {
  daysToDay,
  defaultDuration,
  durationAllowed,
  durationPolicy,
  expiryDateFor,
  formatDay,
  isoDay,
  presetDays,
  resolveDuration,
} from '../scope-entry'

const base = { one_off_targets: 'admins_and_requests', one_off_max_days: 7, t2_max_days: 30 }

describe('durationPolicy', () => {
  it('T2 follows the owner limit; permanent is forbidden unless allowed', () => {
    expect(durationPolicy('t2', base, { isRequest: false })).toEqual({
      maxDays: 30,
      permanent: 'forbidden',
      expiring: true,
    })
    expect(
      durationPolicy(
        't2',
        { ...base, t2_max_days: 365, t2_permanent_allowed: true },
        {
          isRequest: false,
        }
      ).permanent
    ).toBe('allowed')
  })

  it('T1 may be permanent; an expiry follows the one-off limit and policy', () => {
    expect(durationPolicy('t1', base, { isRequest: false })).toEqual({
      maxDays: 7,
      permanent: 'allowed',
      expiring: true,
    })
    expect(
      durationPolicy('t1', { ...base, one_off_targets: 'disabled' }, { isRequest: false }).expiring
    ).toBe(false)
  })

  it('a member request never offers permanent', () => {
    expect(durationPolicy('t1', base, { isRequest: true }).permanent).toBe('hidden')
  })
})

describe('default duration per policy', () => {
  it('is the longest allowed: permanent when allowed, else the day limit', () => {
    expect(defaultDuration(durationPolicy('t1', base, { isRequest: false }))).toEqual({
      kind: 'permanent',
    })
    for (const max of [7, 30, 90, 365]) {
      const p = durationPolicy('t2', { ...base, t2_max_days: max }, { isRequest: false })
      expect(defaultDuration(p)).toEqual({ kind: 'days', days: max })
    }
    expect(defaultDuration(durationPolicy('t1', base, { isRequest: true }))).toEqual({
      kind: 'days',
      days: 7,
    })
  })

  it('never keeps a forbidden choice: permanent switches to the T2 limit', () => {
    const t2 = durationPolicy('t2', base, { isRequest: false })
    expect(durationAllowed({ kind: 'permanent' }, t2)).toBe(false)
    expect(resolveDuration({ kind: 'permanent' }, t2)).toEqual({ kind: 'days', days: 30 })
    expect(resolveDuration({ kind: 'days', days: 90 }, t2)).toEqual({ kind: 'days', days: 30 })
    expect(resolveDuration({ kind: 'days', days: 7 }, t2)).toEqual({ kind: 'days', days: 7 })
    expect(resolveDuration(null, t2)).toEqual({ kind: 'days', days: 30 })
  })

  it('offers the presets under the limit, and the limit itself', () => {
    expect(presetDays(30)).toEqual([7, 30])
    expect(presetDays(365)).toEqual([7, 30, 90, 365])
    expect(presetDays(14)).toEqual([7, 14])
    expect(presetDays(5)).toEqual([5])
  })
})

describe('dates', () => {
  const now = new Date(2026, 9, 10, 15, 30)
  it('counts whole days to a picked day', () => {
    expect(daysToDay('2026-10-11', now)).toBe(1)
    expect(daysToDay('2026-11-09', now)).toBe(30)
    expect(daysToDay('nope', now)).toBe(0)
  })
  it('names the expiry day', () => {
    expect(isoDay(expiryDateFor(30, now))).toBe('2026-11-09')
    expect(formatDay(expiryDateFor(30, now))).toBe('9 Nov 2026')
  })
})
