import { describe, expect, it } from 'vitest'
import { pageSizeChoices } from '../page-size-options'

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
