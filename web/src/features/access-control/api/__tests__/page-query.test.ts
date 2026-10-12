import { describe, expect, it } from 'vitest'
import { pageQuery } from '../use-groups'

// The group member and asset lists page with page / per_page (one list
// convention); the sheet keeps an offset, turned into its page here.
describe('pageQuery', () => {
  it('turns an offset window into page and per_page', () => {
    expect(pageQuery(20, 0)).toBe('page=1&per_page=20')
    expect(pageQuery(20, 40)).toBe('page=3&per_page=20')
  })

  it('never sends a page below 1 or a size below 1', () => {
    expect(pageQuery(0, -5)).toBe('page=1&per_page=1')
  })
})
