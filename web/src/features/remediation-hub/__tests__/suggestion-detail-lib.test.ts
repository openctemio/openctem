/** Pure helpers of the suggestion detail panel. */

import { describe, expect, it } from 'vitest'
import { ApiClientError } from '@/lib/api/error-handler'
import {
  acceptPreview,
  basisFactors,
  claimConflicts,
  confidenceBand,
  crossesMajor,
  earliestDue,
  memberLocation,
  suggestionParam,
} from '../lib/suggestion-detail'

describe('basis and confidence', () => {
  it('reads the recorded factors in a stable order and ignores unknown ones', () => {
    expect(
      basisFactors({
        key_kind: 'sol',
        fix_spec: { basis: ['same_rule', 'x', 'same_specific_solution_text'] },
      })
    ).toEqual(['same_specific_solution_text', 'same_rule'])
  })
  it('falls back to the key kind when nothing is recorded', () => {
    expect(basisFactors({ key_kind: 'upgrade', fix_spec: {} })).toEqual(['same_package_target'])
  })
  it('bands the confidence', () => {
    expect(confidenceBand(1)).toBe('exact')
    expect(confidenceBand(0.9)).toBe('high')
    expect(confidenceBand(0.7)).toBe('medium')
    expect(confidenceBand(0.6)).toBe('low')
  })
})

describe('upgrade hints', () => {
  it('flags a major version change only', () => {
    expect(crossesMajor('3.2.1', '4.2.30')).toBe(true)
    expect(crossesMajor('4.1.0', '4.2.30')).toBe(false)
    expect(crossesMajor(undefined, '4.2.30')).toBe(false)
  })
})

describe('accept preview', () => {
  const s = {
    kind: 'new_group' as const,
    member_count: 3,
    partitions: [
      {
        owner_group_id: 'g',
        owner_rule: 'asset_owner' as const,
        finding_ids: ['a', 'b'],
        risk_points: 2,
      },
      { owner_rule: 'default_queue' as const, finding_ids: ['c'], risk_points: 1 },
    ],
  }
  it('counts one task per owner with findings left', () => {
    const p = acceptPreview(s, new Set(['c']))
    expect(p.tasks).toHaveLength(1)
    expect(p.tasks[0]).toMatchObject({ index: 0, findings: 2, ownerGroupId: 'g', assetOwner: true })
    expect(p.kept).toBe(2)
  })
  it('says a join adds to the existing task', () => {
    expect(acceptPreview({ ...s, kind: 'join' }, new Set()).joins).toBe(true)
  })
  it('takes the earliest SLA of the kept findings', () => {
    const ms = [
      { finding_id: 'a', sla_deadline: '2026-11-05T00:00:00Z' },
      { finding_id: 'b', sla_deadline: '2026-11-01T00:00:00Z' },
    ]
    expect(earliestDue(ms)).toBe('2026-11-01T00:00:00Z')
    expect(earliestDue(ms, new Set(['b']))).toBe('2026-11-05T00:00:00Z')
  })
})

describe('location and errors', () => {
  it('shows file:line, or the target of a finding without a file', () => {
    const base = {
      finding_id: 'f',
      role: 'primary' as const,
      join_source: '',
      title: '',
      severity: 'high',
      status: 'new',
      verified: false,
    }
    expect(
      memberLocation({ ...base, asset_name: 'shop-api', file_path: 'app/db.py', start_line: 42 })
        .full
    ).toBe('shop-api · app/db.py:42')
    expect(
      memberLocation({ ...base, location_targets: ['https://x.example.com/a', 'b'] }).full
    ).toBe('https://x.example.com/a +1')
  })
  it('reads the conflicts of a 409 and nothing else', () => {
    const c = {
      finding_id: 'f',
      finding_title: 't',
      task_id: 'x',
      task_title: null,
      assignee_user_id: null,
      assignee_group_id: null,
      can_move: false,
    }
    expect(
      claimConflicts(
        new ApiClientError('m', 'FINDINGS_IN_OTHER_TASK', 409, { conflicts: [c, { bad: 1 }] })
      )
    ).toEqual([c])
    expect(claimConflicts(new ApiClientError('m', 'CONFLICT', 409))).toBeNull()
    expect(claimConflicts(new Error('x'))).toBeNull()
  })
  it('accepts only a UUID from the URL', () => {
    expect(suggestionParam('0193a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b')).toBe(
      '0193a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b'
    )
    expect(suggestionParam('../tasks')).toBeUndefined()
    expect(suggestionParam(null)).toBeUndefined()
  })
})
