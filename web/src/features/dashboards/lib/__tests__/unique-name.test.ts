import { describe, expect, it } from 'vitest'
import { uniqueDashboardName } from '../unique-name'

describe('uniqueDashboardName', () => {
  it('keeps a free name', () => {
    expect(uniqueDashboardName('Overview', ['Other'])).toBe('Overview')
  })
  it('numbers a taken name, ignoring case', () => {
    expect(uniqueDashboardName('Overview', ['overview'])).toBe('Overview 2')
    expect(uniqueDashboardName('Overview', ['Overview', 'Overview 2'])).toBe('Overview 3')
  })
  it('uses the base for the copy when given', () => {
    expect(uniqueDashboardName('Overview', ['Overview'], 'Overview (new layout)')).toBe(
      'Overview (new layout)'
    )
  })
})
