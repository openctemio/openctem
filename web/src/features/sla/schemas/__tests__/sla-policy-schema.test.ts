import { describe, expect, it } from 'vitest'

import { DEFAULT_SLA_FORM, slaPolicySchema } from '../sla-policy-schema'

const valid = { ...DEFAULT_SLA_FORM, name: 'Default' }

describe('slaPolicySchema', () => {
  it('accepts the platform defaults', () => {
    expect(slaPolicySchema.safeParse(valid).success).toBe(true)
  })

  it('starts a new policy with the platform P0-P3 windows and notifications on', () => {
    expect([
      DEFAULT_SLA_FORM.p0_days,
      DEFAULT_SLA_FORM.p1_days,
      DEFAULT_SLA_FORM.p2_days,
      DEFAULT_SLA_FORM.p3_days,
    ]).toEqual([2, 5, 15, 30])
    expect(DEFAULT_SLA_FORM.escalation_enabled).toBe(true)
    expect(DEFAULT_SLA_FORM.is_default).toBe(true)
  })

  it('refuses a P0 window longer than P1', () => {
    const r = slaPolicySchema.safeParse({ ...valid, p0_days: 10, p1_days: 5 })
    expect(r.success).toBe(false)
    expect(r.error?.issues[0]?.path).toEqual(['p0_days'])
  })

  it('refuses an out-of-range priority window', () => {
    expect(slaPolicySchema.safeParse({ ...valid, p3_days: 400 }).success).toBe(false)
    expect(slaPolicySchema.safeParse({ ...valid, p0_days: 0 }).success).toBe(false)
  })

  it('still enforces the severity order', () => {
    expect(slaPolicySchema.safeParse({ ...valid, critical_days: 20, high_days: 15 }).success).toBe(
      false
    )
  })

  it('gives informational findings no SLA by default; 0 skips the info order', () => {
    expect(DEFAULT_SLA_FORM.info_days).toBe(0)
    expect(slaPolicySchema.safeParse({ ...valid, info_days: 0, low_days: 60 }).success).toBe(true)
    expect(slaPolicySchema.safeParse({ ...valid, info_days: -1 }).success).toBe(false)
    // An opted-in info window still has to be at least the low window.
    expect(slaPolicySchema.safeParse({ ...valid, info_days: 30, low_days: 60 }).success).toBe(false)
    expect(slaPolicySchema.safeParse({ ...valid, info_days: 120, low_days: 60 }).success).toBe(true)
    // Only info may be 0.
    expect(slaPolicySchema.safeParse({ ...valid, low_days: 0 }).success).toBe(false)
  })
})
