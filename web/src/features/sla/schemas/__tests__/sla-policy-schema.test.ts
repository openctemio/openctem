import { describe, expect, it } from 'vitest'

import { newSlaPolicyForm, slaPolicySchema, type SlaFormWindows } from '../sla-policy-schema'

// Windows as the API reports them (GET /sla-policies/default); the web keeps no copy.
const apiWindows: SlaFormWindows = {
  p0_days: 2,
  p1_days: 5,
  p2_days: 15,
  p3_days: 30,
  critical_days: 2,
  high_days: 15,
  medium_days: 30,
  low_days: 60,
  info_days: 0,
  warning_threshold_pct: 80,
  escalation_enabled: true,
}

const valid = { ...newSlaPolicyForm(apiWindows), name: 'Default' }

describe('slaPolicySchema', () => {
  it('accepts the windows the API reports', () => {
    expect(slaPolicySchema.safeParse(valid).success).toBe(true)
  })

  it('starts a new policy from the API windows, unnamed and default', () => {
    const form = newSlaPolicyForm({ ...apiWindows, p0_days: 3, p3_days: 45 })
    expect([form.p0_days, form.p1_days, form.p2_days, form.p3_days]).toEqual([3, 5, 15, 45])
    expect(form.name).toBe('')
    expect(form.is_default).toBe(true)
    expect(form.escalation_enabled).toBe(true)
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
    expect(slaPolicySchema.safeParse({ ...valid, info_days: 0, low_days: 60 }).success).toBe(true)
    expect(slaPolicySchema.safeParse({ ...valid, info_days: -1 }).success).toBe(false)
    // An opted-in info window still has to be at least the low window.
    expect(slaPolicySchema.safeParse({ ...valid, info_days: 30, low_days: 60 }).success).toBe(false)
    expect(slaPolicySchema.safeParse({ ...valid, info_days: 120, low_days: 60 }).success).toBe(true)
    // Only info may be 0.
    expect(slaPolicySchema.safeParse({ ...valid, low_days: 0 }).success).toBe(false)
  })
})
