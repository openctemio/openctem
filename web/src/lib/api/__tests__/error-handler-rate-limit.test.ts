import { beforeEach, describe, expect, it, vi } from 'vitest'

const toastError = vi.fn()
vi.mock('sonner', () => ({ toast: { error: (...a: unknown[]) => toastError(...a) } }))
vi.mock('@/lib/logger', () => ({
  devLog: { log: vi.fn(), warn: vi.fn(), error: vi.fn() },
}))

import { ApiClientError, handleApiError } from '../error-handler'

// A rate-limited finding page failed four background reads at once and
// stacked four "Too many requests" toasts. Every 429 now shares one toast id,
// so a burst of refused reads shows a single toast.
describe('handleApiError on 429', () => {
  beforeEach(() => toastError.mockReset())

  it('uses one toast id for every refused read', () => {
    for (let i = 0; i < 4; i++) {
      handleApiError(new ApiClientError('Too many requests', 'RATE_LIMIT_EXCEEDED', 429))
    }
    expect(toastError).toHaveBeenCalledTimes(4)
    const ids = new Set(toastError.mock.calls.map((c) => (c[1] as { id?: string })?.id))
    expect(ids.size).toBe(1)
    expect([...ids][0]).toMatch(/^api-error:RATE_LIMIT_EXCEEDED:/)
  })

  it('shows nothing when the caller asked for no toast', () => {
    handleApiError(new ApiClientError('Too many requests', 'RATE_LIMIT_EXCEEDED', 429), {
      showToast: false,
    })
    expect(toastError).not.toHaveBeenCalled()
  })
})
