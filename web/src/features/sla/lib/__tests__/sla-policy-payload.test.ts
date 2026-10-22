import { describe, expect, it } from 'vitest'
import { buildSlaPolicyPayload } from '../sla-policy-payload'
import type { SlaPolicyFormData } from '../../schemas/sla-policy-schema'

const form: SlaPolicyFormData = {
  name: 'Prod',
  description: '',
  is_default: true,
  p0_days: 1,
  p1_days: 3,
  p2_days: 10,
  p3_days: 20,
  critical_days: 1,
  high_days: 7,
  medium_days: 30,
  low_days: 90,
  info_days: 0,
  warning_threshold_pct: 80,
  escalation_enabled: true,
}

describe('buildSlaPolicyPayload', () => {
  it('create sends is_default false even if the form value is true', () => {
    expect(buildSlaPolicyPayload(form, false).is_default).toBe(false)
  })
  it('edit never sends is_default', () => {
    expect('is_default' in buildSlaPolicyPayload(form, true)).toBe(false)
  })
})
