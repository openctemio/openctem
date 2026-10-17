import { describe, expect, it } from 'vitest'

import {
  approvalRequester,
  approvalTabCounts,
  canCancelApproval,
  isOwnApproval,
} from '../approvals'

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

describe('isOwnApproval', () => {
  it("is true only for the viewer's own person request", () => {
    expect(isOwnApproval({ requested_by: 'u1' }, 'u1')).toBe(true)
    expect(isOwnApproval({ requested_by: 'u1' }, 'u2')).toBe(false)
    expect(isOwnApproval({ requested_by: '' }, '')).toBe(false)
    expect(isOwnApproval({ requested_by: '' }, undefined)).toBe(false)
  })
})

describe('approvalRequester', () => {
  it('names the actor, the viewer, a member, or a former member', () => {
    expect(approvalRequester({ requested_by: '', requested_by_actor: 'ai_triage' }, 'u1')).toEqual({
      kind: 'actor',
      actor: 'ai_triage',
    })
    expect(approvalRequester({ requested_by: 'u1', requested_by_name: 'Lan' }, 'u1')).toEqual({
      kind: 'you',
    })
    expect(approvalRequester({ requested_by: 'u2', requested_by_name: 'Lan' }, 'u1')).toEqual({
      kind: 'member',
      name: 'Lan',
    })
    expect(approvalRequester({ requested_by: 'u2' }, 'u1')).toEqual({ kind: 'former' })
  })
})
