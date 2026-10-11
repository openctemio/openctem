import { beforeEach, describe, expect, it, vi } from 'vitest'

vi.mock('@/lib/logger', () => ({
  devLog: { log: vi.fn(), warn: vi.fn(), error: vi.fn() },
}))
vi.mock('sonner', () => ({ toast: { error: vi.fn(), success: vi.fn() } }))

import { toast } from 'sonner'
import { ApiClientError, handleApiError } from '../error-handler'

// A module the organization lost recently stays visible and readable, so a
// refused save must say why; a module that is off stays silent (its pages are
// hidden and a stray request is not something the user can act on).
const msg = "Your organization's plan no longer includes this module: it is read-only for now"

describe('MODULE_NOT_ENABLED', () => {
  beforeEach(() => vi.clearAllMocks())

  it('read-only grace shows the server message', () => {
    handleApiError(
      new ApiClientError(msg, 'MODULE_NOT_ENABLED', 403, {
        module: 'pentest',
        reason: 'read_only_grace',
      })
    )
    expect(toast.error).toHaveBeenCalledWith('Read-only', { description: msg })
  })

  it('a module that is off shows no toast', () => {
    handleApiError(
      new ApiClientError('off', 'MODULE_NOT_ENABLED', 403, {
        module: 'pentest',
        reason: 'disabled_by_admin',
      })
    )
    expect(toast.error).not.toHaveBeenCalled()
  })
})
