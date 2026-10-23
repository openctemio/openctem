import { describe, it, expect } from 'vitest'
import { buildFindingsQuery, buildFindingStatsUrl } from '../../api/use-findings-api'
import { queueContextFilters, verifyQueueQuery, verifyQueueNoCveQuery } from '../verify-queue'

describe('verification queue filters', () => {
  const page = {
    asset_id: 'a1',
    cve_ids: ['CVE-1'],
    search: 'x',
    severities: ['high' as const],
    page: 3,
  }

  it('scopes the count and the view by the same context filters', () => {
    const count = new URL(
      buildFindingStatsUrl({ state: 'all', ...queueContextFilters(page) }),
      'http://x'
    ).searchParams
    const view = buildFindingsQuery(verifyQueueQuery(page))
    for (const k of ['asset_id', 'cve_id']) expect(view.get(k)).toBe(count.get(k))
    // Facets and paging are not part of the queue's scope.
    expect(view.has('q')).toBe(false)
    expect(view.has('severity')).toBe(false)
    expect(view.has('page')).toBe(false)
  })

  it('lists claimed fixes and leaves out pentest findings', () => {
    const q = buildFindingsQuery(verifyQueueQuery({}))
    expect(q.get('status')).toBe('fix_applied')
    expect(q.get('source_not')).toBe('pentest')
  })

  it('has a no-CVE part that is the queue narrowed to findings without a CVE', () => {
    const q = buildFindingsQuery(verifyQueueNoCveQuery({}))
    expect(q.get('status')).toBe('fix_applied')
    expect(q.get('source_not')).toBe('pentest')
    expect(q.get('cve_id_null')).toBe('true')
  })
})
