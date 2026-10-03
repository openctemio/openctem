import { describe, it, expect } from 'vitest'

import { toFindingActivityItems } from '../finding-activity-items'
import type { Activity } from '../../types'
import type { ApiFindingComment } from '../../api/finding-api.types'

const jamie = { id: 'u1', name: 'Jamie', email: 'j@x.test', role: 'analyst' as const }

const activities: Activity[] = [
  {
    id: 'a-created',
    type: 'created',
    actor: 'system',
    content: 'Recorded by Trivy',
    createdAt: '2026-05-10T10:00:00Z',
  },
  {
    id: 'a-status',
    type: 'status_changed',
    actor: jamie,
    previousValue: 'confirmed',
    newValue: 'in_progress',
    reason: 'Picked up in sprint 12',
    metadata: { activityType: 'status_changed' },
    createdAt: '2026-05-11T10:00:00Z',
  },
  {
    id: 'a-sla',
    type: 'status_changed',
    actor: 'system',
    metadata: { activityType: 'sla_breach' },
    createdAt: '2026-05-12T10:00:00Z',
  },
  {
    id: 'a-comment',
    type: 'comment',
    actor: jamie,
    content: 'old text',
    metadata: { activityType: 'comment_added', comment_id: 'c1' },
    createdAt: '2026-05-11T11:00:00Z',
  },
]

const comments: ApiFindingComment[] = [
  {
    id: 'c1',
    finding_id: 'f1',
    author_id: 'u1',
    author_name: 'Jamie',
    content: 'current text',
    is_status_change: false,
    created_at: '2026-05-11T11:00:00Z',
    updated_at: '2026-05-11T12:00:00Z',
    is_internal: true,
    reactions: [{ emoji: '👀', count: 1, reacted_by_me: true, sample_users: [{ name: 'Jamie' }] }],
  },
  {
    id: 'c2',
    finding_id: 'f1',
    author_id: 'u1',
    content: 'Status changed from new to confirmed',
    is_status_change: true,
    created_at: '2026-05-11T09:00:00Z',
  },
]

describe('toFindingActivityItems', () => {
  it('words events without the actor and names the scanner that recorded it', () => {
    const items = toFindingActivityItems(activities, comments)
    const byId = Object.fromEntries(items.map((i) => [i.id, i]))
    expect(byId['a-created']).toMatchObject({
      actor: { name: 'Trivy' },
      summary: 'recorded this finding',
    })
    expect(byId['a-status']).toMatchObject({
      summary: 'changed status Confirmed → In Progress',
      detail: 'Picked up in sprint 12',
    })
    expect(byId['a-sla']).toMatchObject({ summary: 'recorded an SLA breach', tone: 'destructive' })
  })

  it('takes comments from the comment list, once, with Internal, edited and reactions', () => {
    const items = toFindingActivityItems(activities, comments)
    const cs = items.filter((i) => i.kind === 'comment')
    expect(cs).toHaveLength(1)
    expect(cs[0]).toMatchObject({
      commentId: 'c1',
      body: 'current text',
      internal: true,
      editedAt: '2026-05-11T12:00:00Z',
      reactions: [{ emoji: '👀', count: 1, reactedByMe: true, sampleUsers: [{ name: 'Jamie' }] }],
    })
  })

  it('falls back to the activity rows when the comment list is unavailable', () => {
    const cs = toFindingActivityItems(activities, undefined).filter((i) => i.kind === 'comment')
    expect(cs).toHaveLength(1)
    expect(cs[0]).toMatchObject({ commentId: 'c1', body: 'old text' })
  })
})
