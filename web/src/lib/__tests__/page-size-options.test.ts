import { describe, expect, it } from 'vitest'
import { isPhonePageSize, nextPhonePageSize, pageSizeChoices } from '../page-size-options'

describe('pageSizeChoices', () => {
  it('keeps the defaults when the current size is one of them', () => {
    expect(pageSizeChoices([10, 20, 50], 20)).toEqual([10, 20, 50])
  })
  it('adds the size in use, in order', () => {
    expect(pageSizeChoices([10, 20, 30, 50, 100], 25)).toEqual([10, 20, 25, 30, 50, 100])
  })
  it('ignores a size that is not a positive number', () => {
    expect(pageSizeChoices([10, 20], 0)).toEqual([10, 20])
    expect(pageSizeChoices([10, 20], Number.NaN)).toEqual([10, 20])
  })
})

describe('phone page sizes', () => {
  it('accepts the steps of "Show more" up to the largest page the API returns', () => {
    expect([25, 50, 75, 100].every(isPhonePageSize)).toBe(true)
    expect([0, 20, 26, 125, 1000, Number.NaN, 37.5].some(isPhonePageSize)).toBe(false)
  })
  it('grows by one step and stops at the cap', () => {
    expect(nextPhonePageSize(25, 100)).toBe(50)
    expect(nextPhonePageSize(50, 100)).toBe(75)
    expect(nextPhonePageSize(75, 100)).toBe(100)
    expect(nextPhonePageSize(100, 100)).toBeNull()
    expect(nextPhonePageSize(20, 100)).toBe(25)
    expect(nextPhonePageSize(30, 100)).toBe(50)
    expect(nextPhonePageSize(100)).toBe(125)
  })
})
