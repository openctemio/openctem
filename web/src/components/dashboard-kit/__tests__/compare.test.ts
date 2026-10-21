import { describe, expect, it } from 'vitest'
import { ApiClientError } from '@/lib/api/error-handler'
import {
  changeOf,
  deltaTone,
  isStale,
  stageStateOf,
  stateFromError,
  targetStatus,
} from '../compare'

describe('deltaTone follows the figure polarity', () => {
  it('fewer open findings is better, more is worse', () => {
    expect(deltaTone(-12, 'down_good')).toBe('better')
    expect(deltaTone(5, 'down_good')).toBe('worse')
  })
  it('a higher share within SLA is better', () => {
    expect(deltaTone(3, 'up_good')).toBe('better')
    expect(deltaTone(-3, 'up_good')).toBe('worse')
  })
  it('no change is flat, unknown and neutral figures have no tone', () => {
    expect(deltaTone(0, 'down_good')).toBe('flat')
    expect(deltaTone(null, 'down_good')).toBe('neutral')
    expect(deltaTone(4, 'neutral')).toBe('neutral')
  })
  it('changeOf needs both values', () => {
    expect(changeOf(10, 4)).toBe(6)
    expect(changeOf(10, null)).toBeNull()
    expect(changeOf(null, 4)).toBeNull()
  })
})

describe('targetStatus', () => {
  it('compares with the operator and the optional warn bound', () => {
    expect(targetStatus(0, { op: '<=', value: 0 })).toBe('met')
    expect(targetStatus(3, { op: '<=', value: 0, warn: 5 })).toBe('near')
    expect(targetStatus(9, { op: '<=', value: 0, warn: 5 })).toBe('missed')
    expect(targetStatus(96, { op: '>=', value: 95 })).toBe('met')
    expect(targetStatus(86, { op: '>=', value: 95, warn: 85 })).toBe('near')
  })
  it('a figure that was not measured is never on target', () => {
    expect(targetStatus(null, { op: '<=', value: 0 })).toBe('unmeasured')
    expect(stageStateOf('unmeasured')).toBe('unmeasured')
    expect(stageStateOf(null)).toBe('unmeasured')
  })
  it('no target, no status', () => {
    expect(targetStatus(5, null)).toBeNull()
  })
})

describe('isStale', () => {
  const now = new Date('2026-10-21T10:00:00Z')
  it('is stale past twice the refresh interval', () => {
    expect(isStale('2026-10-21T09:00:00Z', 15 * 60_000, false, now)).toBe(true)
    expect(isStale('2026-10-21T09:50:00Z', 15 * 60_000, false, now)).toBe(false)
  })
  it('is stale after a failed refresh, whatever the age', () => {
    expect(isStale('2026-10-21T09:59:00Z', 15 * 60_000, true, now)).toBe(true)
  })
  it('a manual schedule (no interval) is never stale by age', () => {
    expect(isStale('2026-01-01T00:00:00Z', null, false, now)).toBe(false)
  })
})

describe('stateFromError', () => {
  it('tells a refusal from a failure', () => {
    expect(stateFromError(new ApiClientError('x', 'FORBIDDEN', 403))).toBe('no_access')
    expect(stateFromError(new ApiClientError('x', 'MODULE_NOT_ENABLED', 403))).toBe('module_off')
    expect(stateFromError(new ApiClientError('x', 'INTERNAL', 500))).toBe('error')
    expect(stateFromError(undefined)).toBeUndefined()
  })
})
