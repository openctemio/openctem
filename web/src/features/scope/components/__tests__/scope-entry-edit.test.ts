import { describe, expect, it, vi } from 'vitest'

vi.mock('@/context/tenant-provider', () => ({ useTenant: () => ({ currentTenant: null }) }))

const { isWideningChange } = await import('../scope-entry-edit-dialog')

// RFC-054 §6.1: a later or removed expiry, or a higher tier, widens an entry
// (approver + step-up, may go back to pending); the rest narrows.
describe('isWideningChange', () => {
  const inThreeDays = new Date(Date.now() + 3 * 86_400_000).toISOString()
  const oneOff = { expires_at: inThreeDays, max_tier: 't1' }

  it('a later expiry, a removed expiry and a higher tier widen', () => {
    expect(isWideningChange(oneOff, { expires_in_days: 7 })).toBe(true)
    expect(isWideningChange(oneOff, { clear_expiry: true })).toBe(true)
    expect(isWideningChange(oneOff, { max_tier: 't2' })).toBe(true)
  })

  it('an earlier expiry, a lower tier and text changes narrow', () => {
    expect(isWideningChange(oneOff, { expires_in_days: 1 })).toBe(false)
    expect(isWideningChange(oneOff, { max_tier: 't0' })).toBe(false)
    expect(isWideningChange(oneOff, { reason: 'x', description: 'y' })).toBe(false)
    expect(isWideningChange({ max_tier: 't1' }, { expires_in_days: 7 })).toBe(false)
  })
})
