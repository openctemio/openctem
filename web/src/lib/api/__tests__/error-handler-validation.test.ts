import { describe, expect, it, vi } from 'vitest'

vi.mock('@/lib/logger', () => ({
  devLog: { log: vi.fn(), warn: vi.fn(), error: vi.fn() },
}))

import { ApiClientError, getErrorMessage } from '../error-handler'

// The API answers a request that fails validation with 422 "Validation
// failed" and the reasons as [{ field, message }]. The toast said only
// "Validation failed", so a scan with 1,200 targets gave no hint why.
const details = (d: unknown) => d as Record<string, unknown>

describe('getErrorMessage with validation details', () => {
  it('names each field and its reason', () => {
    const err = new ApiClientError(
      'Validation failed',
      'VALIDATION_FAILED',
      422,
      details([
        { field: 'targets', message: 'must be at most 1000 items' },
        { field: 'name', message: 'is required' },
      ])
    )
    expect(getErrorMessage(err)).toBe('targets must be at most 1000 items. name is required')
  })

  it('keeps the message when the details are not reasons', () => {
    const err = new ApiClientError(
      'Validation failed',
      'VALIDATION_FAILED',
      422,
      details([{ x: 1 }])
    )
    expect(getErrorMessage(err)).toBe('Validation failed')
    expect(getErrorMessage(new ApiClientError('Scan not found', 'NOT_FOUND', 404))).toBe(
      'Scan not found'
    )
  })
})
