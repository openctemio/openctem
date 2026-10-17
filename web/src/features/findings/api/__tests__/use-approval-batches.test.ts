/**
 * The batches list filters by source on the server: a task's page asks for
 * its own pending exception instead of paging through everyone's.
 */

import { describe, it, expect } from 'vitest'
import { approvalBatchesUrl } from '../use-approval-batches'

describe('approvalBatchesUrl', () => {
  it('filters by status and by source', () => {
    const url = approvalBatchesUrl(1, 1, 'pending', 'task-1')
    const q = new URL(url, 'http://x').searchParams
    expect(q.get('status')).toBe('pending')
    expect(q.get('source_id')).toBe('task-1')
    expect(q.get('per_page')).toBe('1')
  })

  it('leaves the source out when there is none', () => {
    expect(approvalBatchesUrl(2, 20)).toBe('/api/v1/approvals/batches?page=2&per_page=20')
  })
})
