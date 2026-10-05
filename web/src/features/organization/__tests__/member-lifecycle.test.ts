import { describe, it, expect } from 'vitest'
import { ApiClientError } from '@/lib/api/error-handler'
import {
  FINDINGS_TO_QUEUE,
  buildOffboardInput,
  isDeactivated,
  memberDisplayName,
  missingReassignments,
  reassignCandidates,
  reassignmentConflict,
  requiredReassignments,
} from '../lib/member-lifecycle'
import type { MemberAccessReport } from '../types/member.types'

function report(over: Partial<MemberAccessReport> = {}): MemberAccessReport {
  return {
    membership_id: 'm1',
    user_id: 'u1',
    status: 'active',
    roles: [],
    groups: [],
    api_keys: [],
    campaigns: [],
    direct_grants: 0,
    visible_assets: 0,
    owned_scans: [],
    owned_report_schedules: [],
    owned_workflows: [],
    assigned_findings: 0,
    owned_assets: 0,
    ...over,
  }
}

const owns = report({
  owned_scans: [{ id: 's1', name: 'Nightly' }],
  owned_workflows: [{ id: 'w1', name: 'Flow' }],
  assigned_findings: 3,
  owned_assets: 2,
})

describe('requiredReassignments', () => {
  it('asks for nothing when the member owns nothing', () => {
    expect(requiredReassignments(report())).toEqual([])
  })

  it('asks for every category the member owns something in', () => {
    expect(requiredReassignments(owns)).toEqual(['schedules', 'findings', 'assets'])
    expect(requiredReassignments(report({ owned_report_schedules: [{ id: 'r', name: 'R' }] }))).toEqual([
      'schedules',
    ])
  })
})

describe('missingReassignments and buildOffboardInput', () => {
  it('reports the uncovered categories', () => {
    expect(missingReassignments(owns, {})).toEqual(['schedules', 'findings', 'assets'])
    expect(missingReassignments(owns, { schedulesTo: 'u2', findingsTo: FINDINGS_TO_QUEUE, assetsTo: 'u2' })).toEqual([])
  })

  it('maps "back to the queue" to unassign_findings', () => {
    expect(buildOffboardInput(owns, { schedulesTo: 'u2', findingsTo: FINDINGS_TO_QUEUE, assetsTo: 'u3' })).toEqual({
      schedules_to: 'u2',
      unassign_findings: true,
      assets_to: 'u3',
    })
  })

  it('sends only the categories the member owns something in', () => {
    expect(buildOffboardInput(report(), { schedulesTo: 'u2', findingsTo: 'u2', assetsTo: 'u2' })).toEqual({})
  })
})

describe('deactivated people', () => {
  it('marks disabled and offboarded members', () => {
    expect(isDeactivated('suspended')).toBe(true)
    expect(isDeactivated('offboarded')).toBe(true)
    expect(isDeactivated('active')).toBe(false)
    expect(memberDisplayName({ name: 'Ann', status: 'offboarded' })).toBe('Ann (deactivated)')
    expect(memberDisplayName({ name: 'Bob', status: 'active' })).toBe('Bob')
  })

  it('never offers the leaver or a deactivated person as a new owner', () => {
    const members = [
      { user_id: 'u1', status: 'active' },
      { user_id: 'u2', status: 'active' },
      { user_id: 'u3', status: 'suspended' },
      { user_id: 'u4', status: 'offboarded' },
    ]
    expect(reassignCandidates(members, 'u1').map((m) => m.user_id)).toEqual(['u2'])
  })
})

describe('reassignmentConflict', () => {
  it('reads the missing categories of a 409 reassignment_required', () => {
    const err = new ApiClientError('reassign', 'CONFLICT', 409, {
      code: 'reassignment_required',
      missing: ['schedules', 'assets', 'bogus'],
    })
    expect(reassignmentConflict(err)).toEqual(['schedules', 'assets'])
  })

  it('ignores every other error', () => {
    expect(reassignmentConflict(new ApiClientError('x', 'CONFLICT', 409))).toBeNull()
    expect(reassignmentConflict(new ApiClientError('x', 'BAD', 400, { code: 'reassignment_required', missing: [] }))).toBeNull()
    expect(reassignmentConflict(new Error('x'))).toBeNull()
  })
})
