import { describe, expect, it } from 'vitest'
import { groupRefusals } from '../refusal-groups'
import type { CITokenRefusal } from '../../types'

const refusal = (over: Partial<CITokenRefusal>): CITokenRefusal =>
  ({
    id: 'r',
    at: '2026-11-20T10:00:00Z',
    provider: 'gitlab',
    repository: 'group/app',
    ref: 'refs/heads/feature',
    event: 'push',
    reasons: ['ref_not_allowed'],
    configs: [],
    ...over,
  }) as CITokenRefusal

describe('groupRefusals', () => {
  it('folds identical refusals into one group with the count and the newest time', () => {
    const groups = groupRefusals([
      refusal({ id: 'a', at: '2026-11-20T10:00:00Z' }),
      refusal({ id: 'b', at: '2026-11-22T10:00:00Z' }),
      refusal({ id: 'c', at: '2026-11-21T10:00:00Z' }),
    ])
    expect(groups).toHaveLength(1)
    expect(groups[0].count).toBe(3)
    expect(groups[0].lastAt).toBe('2026-11-22T10:00:00Z')
    expect(groups[0].refusal.id).toBe('b')
  })

  it('keeps refusals of another ref, repository, event or rule apart', () => {
    const groups = groupRefusals([
      refusal({ id: 'a' }),
      refusal({ id: 'b', ref: 'refs/heads/main' }),
      refusal({ id: 'c', repository: 'group/other' }),
      refusal({ id: 'd', event: 'merge_request' }),
      refusal({ id: 'e', reasons: ['repository_not_allowed'] }),
    ])
    expect(groups).toHaveLength(5)
    expect(groups.every((g) => g.count === 1)).toBe(true)
  })

  it('treats the same rules in another order as one group', () => {
    const groups = groupRefusals([
      refusal({ id: 'a', reasons: ['ref_not_allowed', 'ref_not_protected'] }),
      refusal({ id: 'b', reasons: ['ref_not_protected', 'ref_not_allowed'] }),
    ])
    expect(groups).toHaveLength(1)
    expect(groups[0].count).toBe(2)
  })

  it('keeps workflow refusals naming different pipeline files apart', () => {
    const groups = groupRefusals([
      refusal({
        id: 'a',
        reasons: ['workflow_not_allowed'],
        message: 'pipeline definition "a.yml" is not listed',
      }),
      refusal({
        id: 'b',
        reasons: ['workflow_not_allowed'],
        message: 'pipeline definition "b.yml" is not listed',
      }),
    ])
    expect(groups).toHaveLength(2)
  })

  it('orders groups newest first', () => {
    const groups = groupRefusals([
      refusal({ id: 'old', ref: 'refs/heads/old', at: '2026-11-01T00:00:00Z' }),
      refusal({ id: 'new', ref: 'refs/heads/new', at: '2026-11-25T00:00:00Z' }),
    ])
    expect(groups.map((g) => g.refusal.id)).toEqual(['new', 'old'])
  })
})
