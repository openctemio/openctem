import { describe, it, expect } from 'vitest'
import { Activity } from 'lucide-react'

import {
  buildFeedRows,
  collapsedLabel,
  countUnread,
  dayLabel,
  defaultFilter,
  markdownSnippet,
  sortChronological,
} from '../activity-feed'
import type {
  ActivityActor,
  ActivityCommentItem,
  ActivityEventItem,
  ActivityItem,
} from '../../types'

const system: ActivityActor = { name: 'System', kind: 'system' }
const jamie: ActivityActor = { id: 'u-jamie', name: 'Jamie', kind: 'user' }
const an: ActivityActor = { id: 'u-an', name: 'An', kind: 'user' }

function ev(id: string, at: string, actor = system): ActivityEventItem {
  return { kind: 'event', id, at, actor, icon: Activity, summary: `event ${id}` }
}
function cm(id: string, at: string, actor = jamie, body = `comment ${id}`): ActivityCommentItem {
  return { kind: 'comment', id, at, actor, body }
}

const types = (rows: ReturnType<typeof buildFeedRows>) =>
  rows.map((r) =>
    r.type === 'day' ? 'day' : r.type === 'unread' ? 'unread' : `${r.type}:${r.key}`
  )

describe('sortChronological', () => {
  it('puts the oldest first and keeps ties in input order', () => {
    const items = [cm('b', '2026-05-10T10:00:00Z'), cm('a', '2026-05-09T10:00:00Z')]
    expect(sortChronological(items).map((i) => i.id)).toEqual(['a', 'b'])
    const tie = [cm('x', '2026-05-10T10:00:00Z'), cm('y', '2026-05-10T10:00:00Z')]
    expect(sortChronological(tie).map((i) => i.id)).toEqual(['x', 'y'])
  })
})

describe('buildFeedRows', () => {
  it('starts each day with a separator', () => {
    const rows = buildFeedRows([cm('a', '2026-05-09T10:00:00'), cm('b', '2026-05-10T10:00:00')], {
      filter: 'all',
    })
    expect(types(rows)).toEqual(['day', 'comment:a', 'day', 'comment:b'])
  })

  it('folds a run of three or more events into one row, keyed by the first', () => {
    const rows = buildFeedRows(
      [
        cm('c1', '2026-05-10T09:00:00'),
        ev('e1', '2026-05-10T10:00:00'),
        ev('e2', '2026-05-10T10:01:00', jamie),
        ev('e3', '2026-05-10T10:02:00', an),
        cm('c2', '2026-05-10T11:00:00'),
      ],
      { filter: 'all' }
    )
    expect(types(rows)).toEqual(['day', 'comment:c1', 'collapsed:e1', 'comment:c2'])
    const folded = rows[2]
    expect(folded.type === 'collapsed' && folded.actors).toEqual(['System', 'Jamie', 'An'])
  })

  it('keeps a run of two events as rows', () => {
    const rows = buildFeedRows([ev('e1', '2026-05-10T10:00:00'), ev('e2', '2026-05-10T10:01:00')], {
      filter: 'all',
    })
    expect(types(rows)).toEqual(['day', 'event:e1', 'event:e2'])
  })

  it('shows a folded run expanded once the viewer opened it', () => {
    const items = [
      ev('e1', '2026-05-10T10:00:00'),
      ev('e2', '2026-05-10T10:01:00'),
      ev('e3', '2026-05-10T10:02:00'),
    ]
    const rows = buildFeedRows(items, { filter: 'all', expanded: new Set(['e1']) })
    expect(types(rows)).toEqual(['day', 'event:e1', 'event:e2', 'event:e3'])
  })

  it('does not fold in the Changes view, and Comments shows comments only', () => {
    const items: ActivityItem[] = [
      ev('e1', '2026-05-10T10:00:00'),
      ev('e2', '2026-05-10T10:01:00'),
      ev('e3', '2026-05-10T10:02:00'),
      cm('c1', '2026-05-10T10:03:00'),
    ]
    expect(types(buildFeedRows(items, { filter: 'changes' }))).toEqual([
      'day',
      'event:e1',
      'event:e2',
      'event:e3',
    ])
    expect(types(buildFeedRows(items, { filter: 'comments' }))).toEqual(['day', 'comment:c1'])
  })

  it('places the unread divider before the first item newer than the last visit', () => {
    const lastSeenAt = new Date('2026-05-10T10:30:00').getTime()
    const rows = buildFeedRows(
      [
        cm('old', '2026-05-10T10:00:00', an),
        cm('mine', '2026-05-10T11:00:00', jamie),
        cm('new', '2026-05-10T12:00:00', an),
      ],
      { filter: 'all', lastSeenAt, viewerId: 'u-jamie' }
    )
    // The viewer's own comment is never "new" to them.
    expect(types(rows)).toEqual(['day', 'comment:old', 'comment:mine', 'unread', 'comment:new'])
  })

  it('has no divider on a first visit or when nothing was seen before', () => {
    const items = [cm('a', '2026-05-10T10:00:00', an)]
    expect(types(buildFeedRows(items, { filter: 'all', lastSeenAt: null }))).not.toContain('unread')
    expect(types(buildFeedRows(items, { filter: 'all', lastSeenAt: 0 }))).not.toContain('unread')
  })

  it('drops duplicate ids (a live item that was also refetched)', () => {
    const rows = buildFeedRows([cm('a', '2026-05-10T10:00:00'), cm('a', '2026-05-10T10:00:00')], {
      filter: 'all',
    })
    expect(types(rows)).toEqual(['day', 'comment:a'])
  })
})

describe('helpers', () => {
  it('opens on Comments when there are any', () => {
    expect(defaultFilter([ev('e', '2026-05-10T10:00:00')])).toBe('all')
    expect(defaultFilter([ev('e', '2026-05-10T10:00:00'), cm('c', '2026-05-10T10:00:00')])).toBe(
      'comments'
    )
  })

  it('counts unread items, not the viewer’s own or pending ones', () => {
    const items: ActivityItem[] = [
      cm('a', '2026-05-10T12:00:00', an),
      cm('b', '2026-05-10T12:00:00', jamie),
      { ...cm('c', '2026-05-10T12:00:00', an), pending: 'sending' },
    ]
    expect(countUnread(items, new Date('2026-05-10T11:00:00').getTime(), 'u-jamie')).toBe(1)
    expect(countUnread(items, null, 'u-jamie')).toBe(0)
  })

  it('labels a folded run', () => {
    expect(collapsedLabel(12, ['System', 'Jamie', 'An'])).toBe('12 changes by System and 2 others')
    expect(collapsedLabel(3, ['System', 'Jamie'])).toBe('3 changes by System and 1 other')
    expect(collapsedLabel(3, ['System'])).toBe('3 changes by System')
  })

  it('labels days relative to now', () => {
    const now = new Date('2026-05-12T15:00:00')
    expect(dayLabel(new Date('2026-05-12T01:00:00'), now)).toBe('Today')
    expect(dayLabel(new Date('2026-05-11T23:00:00'), now)).toBe('Yesterday')
    expect(dayLabel(new Date('2026-05-10T10:00:00'), now)).toBe('May 10')
    expect(dayLabel(new Date('2025-05-10T10:00:00'), now)).toBe('May 10, 2025')
  })

  it('makes a plain-text snippet without markup or link targets', () => {
    expect(
      markdownSnippet('**Fixed** in [PR 12](javascript:alert(1)) — see `cfg.yaml`\n\n<img src=x>')
    ).toBe('Fixed in PR 12 — see cfg.yaml')
    expect(markdownSnippet('a '.repeat(200), 20).endsWith('…')).toBe(true)
  })
})
