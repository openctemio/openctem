import { beforeEach, describe, expect, it, vi } from 'vitest'

vi.mock('@/lib/logger', () => ({
  devLog: { log: vi.fn(), warn: vi.fn(), error: vi.fn() },
}))
vi.mock('sonner', () => ({ toast: { error: vi.fn(), success: vi.fn() } }))

import { toast } from 'sonner'
import { ApiClientError, getErrorMessage, handleApiError } from '../error-handler'

// The API answers a status change that needs an approver (false positive,
// accepted risk) with 403 APPROVAL_REQUIRED and a message naming the permission
// the approver needs. A generic 403 toast ("You do not have permission ...")
// told the user nothing they could act on.
const msg =
  'Changing a finding to false positive needs approval from a user with the findings:approve permission. Submit an approval request instead.'

describe('APPROVAL_REQUIRED', () => {
  beforeEach(() => vi.clearAllMocks())

  it('handleApiError shows the server message under an "Approval required" title', () => {
    handleApiError(
      new ApiClientError(msg, 'APPROVAL_REQUIRED', 403, { required_permission: 'findings:approve' })
    )
    expect(toast.error).toHaveBeenCalledWith('Approval required', { description: msg })
  })

  it('getErrorMessage returns the server message', () => {
    expect(getErrorMessage(new ApiClientError(msg, 'APPROVAL_REQUIRED', 403))).toBe(msg)
  })

  it('a plain FORBIDDEN keeps the generic permission message', () => {
    handleApiError(new ApiClientError('Access denied', 'FORBIDDEN', 403))
    expect(toast.error).toHaveBeenCalledWith('Error', {
      description: 'You do not have permission to access this resource',
    })
  })
})
