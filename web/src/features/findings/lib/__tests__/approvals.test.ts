import { describe, expect, it } from 'vitest'

import { approvalTabCounts, canCancelApproval } from '../approvals'

describe('approvalTabCounts', () => {
  it('sums the server counts for All and fills missing statuses with 0', () => {
    const c = approvalTabCounts({ pending: 3, approved: 2 })
    expect(c).toEqual({ all: 5, pending: 3, approved: 2, rejected: 0, canceled: 0, expired: 0 })
    expect(approvalTabCounts(undefined).all).toBe(0)
  })
})

describe('canCancelApproval', () => {
  it('lets only the requester cancel a pending request', () => {
    expect(canCancelApproval({ status: 'pending', requested_by: 'u1' }, 'u1')).toBe(true)
    expect(canCancelApproval({ status: 'pending', requested_by: 'u1' }, 'u2')).toBe(false)
    expect(canCancelApproval({ status: 'approved', requested_by: 'u1' }, 'u1')).toBe(false)
    expect(canCancelApproval({ status: 'pending', requested_by: 'u1' }, undefined)).toBe(false)
  })
})
