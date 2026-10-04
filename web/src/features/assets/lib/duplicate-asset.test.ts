import { describe, it, expect, vi, beforeEach } from 'vitest'

vi.mock('sonner', () => ({ toast: { error: vi.fn() } }))

import { toast } from 'sonner'
import { ApiClientError } from '@/lib/api/error-handler'
import { duplicateAssetConflict, toastIfDuplicateAsset } from './duplicate-asset'

const ID = '019f5efa-3cd1-75cc-8804-0b00ff896af8'

describe('duplicateAssetConflict', () => {
  it('reads the existing asset id from a 409', () => {
    const err = new ApiClientError('Asset already exists', 'CONFLICT', 409, {
      existing_asset_id: ID,
    })
    expect(duplicateAssetConflict(err)).toEqual({ existingAssetId: ID })
  })

  it('is a generic conflict when the 409 names no asset (out of scope)', () => {
    const err = new ApiClientError('Asset already exists', 'CONFLICT', 409)
    expect(duplicateAssetConflict(err)).toEqual({ existingAssetId: undefined })
  })

  it('ignores an id that is not an asset id', () => {
    const err = new ApiClientError('x', 'CONFLICT', 409, {
      existing_asset_id: 'javascript:alert(1)',
    })
    expect(duplicateAssetConflict(err)).toEqual({ existingAssetId: undefined })
  })

  it('is undefined for other errors', () => {
    expect(duplicateAssetConflict(new ApiClientError('bad', 'BAD_REQUEST', 400))).toBeUndefined()
    expect(duplicateAssetConflict(new Error('boom'))).toBeUndefined()
  })
})

describe('toastIfDuplicateAsset', () => {
  beforeEach(() => vi.mocked(toast.error).mockClear())

  it('offers to open the existing asset when the API named it', () => {
    const navigate = vi.fn()
    const err = new ApiClientError('Asset already exists', 'CONFLICT', 409, {
      existing_asset_id: ID,
    })
    expect(toastIfDuplicateAsset(err, navigate)).toBe(true)
    const opts = vi.mocked(toast.error).mock.calls[0][1] as {
      action?: { onClick: () => void }
    }
    opts.action?.onClick()
    expect(navigate).toHaveBeenCalledWith(`/assets/${ID}`)
  })

  it('has no link for a generic conflict', () => {
    const err = new ApiClientError('Asset already exists', 'CONFLICT', 409)
    expect(toastIfDuplicateAsset(err, vi.fn())).toBe(true)
    const opts = vi.mocked(toast.error).mock.calls[0][1] as { action?: unknown }
    expect(opts.action).toBeUndefined()
  })

  it('leaves other errors to the caller', () => {
    expect(toastIfDuplicateAsset(new Error('boom'), vi.fn())).toBe(false)
    expect(toast.error).not.toHaveBeenCalled()
  })
})
