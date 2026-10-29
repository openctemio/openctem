import { describe, expect, it } from 'vitest'
import type { ApiSlaBasis } from '../../../api/finding-api.types'
import { slaWhyLines } from '../sla-why-this-date'

const t = (_k: string, fallback: string, vars?: Record<string, string | number>) =>
  fallback.replace(/\{(\w+)\}/g, (_, k) => String(vars?.[k] ?? ''))
const fmt = (iso: string) => iso.slice(0, 10)
const base: ApiSlaBasis = {
  policy_id: 'p1',
  policy_name: 'Production',
  policy_scope: 'organization',
  basis: 'priority',
  days: 7,
  kev_cap_days: 2,
  kev_capped: false,
  clock_started_at: '2026-10-19T00:00:00Z',
  clock_reason: 'first_detected',
  restarts: 0,
}

describe('slaWhyLines', () => {
  it('names the window, its source and the clock start', () => {
    expect(slaWhyLines(base, { priorityClass: 'P1' }, t, fmt)).toEqual([
      '7 days for priority P1, from the organization policy Production.',
      'The clock started on 2026-10-19, when it was first detected.',
    ])
  })

  it('explains a reopen restart, the KEV cap and an earlier date', () => {
    const lines = slaWhyLines(
      {
        ...base,
        clock_reason: 'reopened',
        last_restart_trigger: 'retest',
        restarts: 2,
        kev_capped: true,
        earlier: true,
      },
      { priorityClass: 'P0' },
      t,
      fmt
    )
    expect(lines[1]).toBe('The clock restarted on 2026-10-19, when a retest found it again.')
    expect(lines).toContain('Restarted 2 times by regressions.')
    expect(lines).toContain('Shortened to 2 days because it is in CISA KEV.')
    expect(lines.at(-1)).toMatch(/^Earlier than this window/)
  })

  it('says when there is no SLA, and names the platform defaults', () => {
    expect(slaWhyLines({ ...base, basis: 'none', policy_scope: 'platform' }, {}, t, fmt)).toEqual([
      'No deadline: informational findings get no SLA under the platform defaults (no SLA policy is set up).',
    ])
  })

  it('uses severity when no class window applies', () => {
    expect(
      slaWhyLines({ ...base, basis: 'severity', days: 30 }, { severity: 'medium' }, t, fmt)[0]
    ).toBe('30 days for medium severity, from the organization policy Production.')
  })
})
