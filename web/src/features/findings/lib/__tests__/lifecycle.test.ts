import { describe, it, expect } from 'vitest'
import { ApiClientError } from '@/lib/api/error-handler'
import { LIFECYCLE_KEY_PATTERN, isPlanLimitError, planLimit, slugKey } from '../lifecycle'
import { parseConditionValue } from '../../components/lifecycle/condition-editor'

describe('lifecycle helpers', () => {
  it('derives keys the API accepts', () => {
    expect(slugKey('In review')).toBe('in_review')
    expect(slugKey('Đang xem xét')).toBe('dang_xem_xet')
    expect(slugKey('42 Waiting for vendor!')).toBe('waiting_for_vendor')
    expect(LIFECYCLE_KEY_PATTERN.test(slugKey('A'.repeat(80)))).toBe(true)
  })

  it('reads plan limits: -1 or absent is unlimited', () => {
    expect(planLimit(undefined, 'lifecycle_schemes')).toBeNull()
    expect(
      planLimit([{ key: 'lifecycle_schemes', limit: -1, used: 4 }], 'lifecycle_schemes')
    ).toBeNull()
    expect(
      planLimit([{ key: 'lifecycle_schemes', limit: 1, used: 1 }], 'lifecycle_schemes')
    ).toEqual({
      limit: 1,
      used: 1,
      reached: true,
    })
  })

  it('recognises a plan-limit refusal', () => {
    expect(isPlanLimitError(new ApiClientError('x', 'PLAN_LIMIT', 403))).toBe(true)
    expect(isPlanLimitError(new ApiClientError('x', 'FORBIDDEN', 403))).toBe(false)
  })

  it('types condition values as the API expects', () => {
    expect(parseConditionValue('severity', 'in', 'high, critical')).toEqual(['high', 'critical'])
    expect(parseConditionValue('is_kev', 'eq', 'true')).toBe(true)
    expect(parseConditionValue('source', 'exists', '')).toBe(true)
    expect(parseConditionValue('priority_class', 'gte', ' P1 ')).toBe('P1')
  })
})
