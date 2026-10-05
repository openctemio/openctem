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
})
