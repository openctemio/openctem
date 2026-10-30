import { describe, expect, it } from 'vitest'
import {
  acceptanceDays,
  approvalQueueEndpoint,
  findingsQueueEndpoint,
  parseTab,
} from '../lib/queues'

describe('My Work queues', () => {
  it('opens the tab in the URL only when the caller has it', () => {
    expect(parseTab('review', ['assigned', 'review'])).toBe('review')
    expect(parseTab('review', ['assigned', 'team'])).toBe('assigned')
    expect(parseTab(null, ['assigned', 'team'])).toBe('assigned')
    expect(parseTab('<script>', ['team'])).toBe('team')
  })

  it("lists a view with the view's own filter plus paging and order only", () => {
    const url = findingsQueueEndpoint(
      'state=open&related_to=me&informational=false',
      'sla_deadline'
    )
    const q = new URL(url, 'http://x').searchParams
    expect(url.startsWith('/api/v1/findings?')).toBe(true)
    expect(q.get('state')).toBe('open')
    expect(q.get('related_to')).toBe('me')
    expect(q.get('informational')).toBe('false')
    expect(q.get('sort')).toBe('sla_deadline')
    expect(q.get('page')).toBe('1')
    expect(q.get('per_page')).toBe('15')
    expect([...q.keys()].sort()).toEqual(
      ['informational', 'page', 'per_page', 'related_to', 'sort', 'state'].sort()
    )
  })

  it('asks the approvals API for one pending personal queue', () => {
    expect(approvalQueueEndpoint('review', 25)).toBe(
      '/api/v1/approvals?queue=review&status=pending&page=1&per_page=25'
    )
    expect(approvalQueueEndpoint('requested', 1)).toContain('queue=requested')
  })

  it('names how long an acceptance would last', () => {
    expect(acceptanceDays('2026-01-01T00:00:00Z', '2026-04-01T00:00:00Z')).toBe(90)
    expect(acceptanceDays('2026-01-01T00:00:00Z', undefined)).toBeNull()
    expect(acceptanceDays('2026-02-01T00:00:00Z', '2026-01-01T00:00:00Z')).toBeNull()
  })
})
