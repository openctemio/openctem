import { beforeEach, describe, expect, it, vi } from 'vitest'

vi.mock('@/lib/logger', () => ({
  devLog: { log: vi.fn(), warn: vi.fn(), error: vi.fn() },
}))
vi.mock('sonner', () => ({ toast: { error: vi.fn(), success: vi.fn() } }))

import { toast } from 'sonner'
import { ApiClientError, getErrorMessage, handleApiError } from '../error-handler'
import { describePermissionDenied } from '../permission-denied'

// A 403 from a permission or team-role gate names what was missing, so the
// person can ask an administrator for exactly that grant.
describe('permission denied explanation', () => {
  beforeEach(() => vi.clearAllMocks())

  it('names a missing permission with its label and id', () => {
    const why = describePermissionDenied({ missing_permissions: ['findings:verify'] })
    expect(why).toContain('(findings:verify)')
    expect(why).toMatch(/^You need the permission /)
  })

  it('names several missing permissions', () => {
    const why = describePermissionDenied({
      missing_permissions: ['findings:write', 'ai_triage:trigger'],
    })
    expect(why).toMatch(/^You need the permissions /)
    expect(why).toContain('(findings:write)')
    expect(why).toContain('(ai_triage:trigger)')
  })

  it('names the alternatives of an any-of gate', () => {
    const why = describePermissionDenied({ any_of: ['sensors:read', 'scans:ci:read'] })
    expect(why).toMatch(/^You need one of these permissions: /)
    expect(why).toContain('(scans:ci:read)')
  })

  it('names the required team role', () => {
    expect(describePermissionDenied({ required_role: 'admin' })).toBe(
      'Only an organization administrator can do this.'
    )
    expect(describePermissionDenied({ required_role: 'owner' })).toBe(
      'Only the organization owner can do this.'
    )
  })

  it('returns null when nothing is named', () => {
    expect(describePermissionDenied(undefined)).toBeNull()
    expect(describePermissionDenied({})).toBeNull()
    expect(describePermissionDenied({ missing_permissions: [1, null] })).toBeNull()
  })

  it('handleApiError shows the explanation under "Permission needed"', () => {
    handleApiError(
      new ApiClientError('Insufficient permissions', 'FORBIDDEN', 403, {
        missing_permissions: ['findings:verify'],
      })
    )
    expect(toast.error).toHaveBeenCalledWith(
      'Permission needed',
      expect.objectContaining({ description: expect.stringContaining('(findings:verify)') })
    )
  })

  it('getErrorMessage returns the explanation', () => {
    const err = new ApiClientError('Insufficient permissions', 'FORBIDDEN', 403, {
      required_role: 'owner',
    })
    expect(getErrorMessage(err)).toBe('Only the organization owner can do this.')
  })

  it('a FORBIDDEN without details keeps the generic message', () => {
    handleApiError(new ApiClientError('Access denied', 'FORBIDDEN', 403))
    expect(toast.error).toHaveBeenCalledWith('Error', {
      description: 'You do not have permission to access this resource',
    })
  })
})
