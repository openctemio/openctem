import { describe, expect, it } from 'vitest'
import { toFindingActivityItems } from './finding-activity-items'
import type { Activity } from '../types/finding.types'

const base = { actor: 'system' as const, createdAt: '2026-10-22T00:00:00Z' }

describe('comment tombstones', () => {
  it('shows a placeholder for a deleted comment and hides its withheld original', () => {
    const acts = [
      {
        ...base,
        id: 'a1',
        type: 'comment',
        metadata: { activityType: 'comment_added', comment_id: 'c1', deleted: true },
      },
      {
        ...base,
        id: 'a2',
        type: 'comment',
        metadata: { activityType: 'comment_deleted', comment_id: 'c1' },
      },
    ] as unknown as Activity[]
    const items = toFindingActivityItems(acts, undefined)
    expect(items).toHaveLength(1)
    expect(items[0].kind).toBe('event')
  })
})
