import { describe, expect, it } from 'vitest'

import { ApiClientError } from '@/lib/api/error-handler'

import {
  blockingNames,
  decisionLabel,
  holdText,
  isNeverOpensRefusal,
  waitsSummary,
} from '../lib/decision'
import { emptyPolicyForm, formToRequest, policyFormErrors, policyToForm } from '../lib/policy-form'
import { describeDays, describeSlot, zonedLocalToUtc } from '../lib/schedule'
import { isEmptySelector, selectorSummary } from '../lib/selector'

describe('schedule', () => {
  it('describes days and slots, including overnight and 24-hour slots', () => {
    expect(describeDays([5, 1, 2, 3, 4])).toBe('Weekdays')
    expect(describeDays([7, 6])).toBe('Weekends')
    expect(describeDays([1, 2, 3, 4, 5, 6, 7])).toBe('Every day')
    expect(describeDays([1, 3])).toBe('Mon, Wed')
    expect(describeSlot({ days: [6], start: '22:00', end: '06:00' })).toBe(
      'Sat 22:00–06:00 (next day)'
    )
    expect(describeSlot({ days: [1], start: '08:00', end: '08:00' })).toBe(
      'Mon, 24 hours from 08:00'
    )
    expect(describeSlot({ days: [1, 2, 3, 4, 5], start: '09:00', end: '17:00' })).toBe(
      'Weekdays 09:00–17:00'
    )
  })

  it('reads a wall-clock time in the policy zone as an instant, across DST', () => {
    expect(zonedLocalToUtc('2026-10-05T09:00', 'Europe/Berlin')?.toISOString()).toBe(
      '2026-10-05T07:00:00.000Z'
    )
    expect(zonedLocalToUtc('2026-12-05T09:00', 'Europe/Berlin')?.toISOString()).toBe(
      '2026-12-05T08:00:00.000Z'
    )
    expect(zonedLocalToUtc('2026-10-05T09:00', 'Asia/Ho_Chi_Minh')?.toISOString()).toBe(
      '2026-10-05T02:00:00.000Z'
    )
    expect(zonedLocalToUtc('not a date', 'UTC')).toBeNull()
  })
})

describe('policy form', () => {
  it('starts as business hours on weekdays and sends what the API expects', () => {
    const f = { ...emptyPolicyForm('Europe/Berlin'), name: '  Prod hours ' }
    f.selector = { tags: ['prod'], asset_group_ids: [] }
    f.oneOffs = [{ startsLocal: '2026-12-20T00:00', endsLocal: '2026-12-21T00:00' }]
    f.rateLimitRps = '20'
    expect(policyFormErrors(f)).toEqual({})
    const req = formToRequest(f)
    expect(req.name).toBe('Prod hours')
    expect(req.slots).toEqual([{ days: [1, 2, 3, 4, 5], start: '09:00', end: '17:00' }])
    expect(req.one_offs).toEqual([
      { starts_at: '2026-12-19T23:00:00.000Z', ends_at: '2026-12-20T23:00:00.000Z' },
    ])
    expect(req.selector).toEqual({ tags: ['prod'] })
    expect(req.rate_limit_rps).toBe(20)
    expect(req.grace_minutes).toBe(15)
  })

  it('accepts an overnight slot and drops caps on a blackout', () => {
    const f = { ...emptyPolicyForm('UTC'), name: 'Patch night', kind: 'blackout' as const }
    f.slots = [{ days: [6], start: '22:00', end: '06:00' }]
    f.rateLimitRps = '5'
    f.maxConcurrent = '2'
    expect(policyFormErrors(f)).toEqual({})
    const req = formToRequest(f)
    expect(req.rate_limit_rps).toBe(0)
    expect(req.max_concurrent).toBe(0)
  })

  it('reports what the API would refuse', () => {
    const f = { ...emptyPolicyForm('UTC'), name: '' }
    f.slots = [
      { days: [], start: '09:00', end: '17:00' },
      { days: [1], start: '9', end: '17:00' },
    ]
    f.oneOffs = [
      { startsLocal: '2026-10-02T00:00', endsLocal: '2026-10-01T00:00' },
      { startsLocal: '2026-10-01T00:00', endsLocal: '2026-11-15T00:00' },
    ]
    f.graceMinutes = '300'
    f.maxConcurrent = '0'
    const e = policyFormErrors(f)
    expect(e.name).toBe('Name is required.')
    expect(e['slots.0']).toBe('Pick at least one day.')
    expect(e['slots.1']).toBe('Enter a start and an end time.')
    expect(e['oneOffs.0']).toBe('The end must be after the start.')
    expect(e['oneOffs.1']).toBe('A dated window lasts at most 31 days.')
    expect(e.graceMinutes).toBeDefined()
    expect(e.maxConcurrent).toBeDefined()
    expect(
      policyFormErrors({ ...emptyPolicyForm('UTC'), name: 'x', slots: [] }).windows
    ).toBeDefined()
  })

  it('round-trips a stored policy', () => {
    const form = policyToForm({
      id: 'p1',
      name: 'Freeze',
      kind: 'blackout',
      min_tier: 2,
      timezone: 'Europe/Berlin',
      slots: [],
      one_offs: [{ starts_at: '2026-12-19T23:00:00Z', ends_at: '2026-12-26T23:00:00Z' }],
      grace_minutes: 0,
      enabled: false,
      selector: { scan_zone_ids: ['z1'] },
    })
    expect(form.oneOffs[0]).toEqual({
      startsLocal: '2026-12-20T00:00',
      endsLocal: '2026-12-27T00:00',
    })
    const req = formToRequest(form)
    expect(req.one_offs?.[0].starts_at).toBe('2026-12-19T23:00:00.000Z')
    expect(req.min_tier).toBe(2)
    expect(req.enabled).toBe(false)
    expect(req.selector).toEqual({ scan_zone_ids: ['z1'] })
  })
})

describe('selector', () => {
  it('summarises dimensions and hides names the caller cannot read', () => {
    expect(isEmptySelector({})).toBe(true)
    expect(selectorSummary({})).toBe('Every target')
    const s = selectorSummary(
      { tags: ['prod'], asset_group_ids: ['g1', 'g2'] },
      { asset_group_ids: new Map([['g1', 'Payments']]) }
    )
    expect(s).toContain('Tags: prod')
    expect(s).toContain('Payments')
    expect(s).toContain('1 hidden')
  })
})

describe('decisions', () => {
  const blocking = [
    { source_id: 'p1', name: 'Business hours', kind: 'allow' as const, origin: 'policy' as const },
    {
      source_id: 'program:x',
      name: 'Acme VDP',
      kind: 'allow' as const,
      origin: 'program' as const,
    },
  ]

  it('labels each state', () => {
    expect(decisionLabel({ governed: false, open: true })).toBe('No scan window applies')
    expect(decisionLabel({ governed: true, open: true })).toBe('Open now')
    expect(decisionLabel({ governed: true, open: false, never: true })).toBe('Never opens')
    expect(
      decisionLabel({ governed: true, open: false, next_open_at: '2026-10-12T07:00:00Z' })
    ).toMatch(/^Waits until /)
  })

  it('names policies and programs apart', () => {
    expect(blockingNames(blocking)).toBe('Business hours (policy), Acme VDP (bug-bounty program)')
  })

  it('explains each hold of a queued task', () => {
    expect(holdText({ reason: 'window', blocking, next_open_at: '2026-10-12T07:00:00Z' })).toMatch(
      /^Waiting for scan window Business hours \(policy\), Acme VDP \(bug-bounty program\), opens at /
    )
    expect(holdText({ reason: 'window', blocking, never: true })).toContain(
      'never opens: fix the policy'
    )
    expect(holdText({ reason: 'concurrency', blocking: [blocking[0]] })).toContain(
      'concurrency cap'
    )
    expect(holdText({ reason: 'closed', next_open_at: '2026-10-12T07:00:00Z' })).toContain(
      'closed while it was running'
    )
  })

  it('summarises the targets of a run that wait', () => {
    expect(
      waitsSummary({
        waiting_count: 1,
        waiting: [{ target: 'a', next_open_at: '2026-10-12T07:00:00Z' }],
      })
    ).toMatch(/^1 target waits for its scan window; it opens /)
    expect(
      waitsSummary({
        waiting_count: 3,
        waiting: [
          { target: 'a', next_open_at: '2026-10-12T07:00:00Z' },
          { target: 'b', next_open_at: '2026-10-13T07:00:00Z' },
        ],
      })
    ).toMatch(/^3 targets wait for their scan windows; the first opens .*, the last /)
  })

  it('recognises the never-opens refusal', () => {
    expect(isNeverOpensRefusal(new ApiClientError('x', 'SCAN_WINDOW_NEVER_OPENS', 409))).toBe(true)
    expect(isNeverOpensRefusal(new ApiClientError('x', 'CONFLICT', 409))).toBe(false)
    expect(isNeverOpensRefusal(new Error('x'))).toBe(false)
  })
})
