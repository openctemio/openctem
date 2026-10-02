import { describe, expect, it } from 'vitest'

import { summarizeBulkResult } from '../bulk-result'

// POST /findings/bulk/status and /bulk/assign answer 200 with
// { updated, failed, errors } even when nothing changed. The page used to toast
// "Updated N findings" on any 200, so a bulk change to false positive that the
// approval gate refused for every finding reported success.
describe('summarizeBulkResult', () => {
  it('reports full success', () => {
    expect(summarizeBulkResult({ updated: 3, failed: 0 }, 3, 'Updated')).toEqual({
      kind: 'success',
      message: 'Updated 3 findings',
    })
  })

  it('reports a partial failure with the first reason, without the finding id', () => {
    const r = summarizeBulkResult(
      {
        updated: 1,
        failed: 2,
        errors: [
          '01a0fd40-a7c3-7119-980e-9abf5e203d0f: changing to false positive needs approval from a user with the findings:approve permission; submit an approval request instead',
          'x: other',
        ],
      },
      3,
      'Updated'
    )
    expect(r.kind).toBe('warning')
    expect(r.message).toBe('Updated 1 of 3 findings. 2 not changed')
    expect(r.description).toBe(
      'changing to false positive needs approval from a user with the findings:approve permission; submit an approval request instead'
    )
  })

  it('reports a total failure as an error', () => {
    const r = summarizeBulkResult({ updated: 0, failed: 2, errors: ['id: nope'] }, 2, 'Updated')
    expect(r.kind).toBe('error')
    expect(r.message).toBe('No findings were changed')
    expect(r.description).toBe('nope')
  })

  it('falls back to the requested count when the body has no counts', () => {
    expect(summarizeBulkResult(undefined, 2, 'Assigned')).toEqual({
      kind: 'success',
      message: 'Assigned 2 findings',
    })
  })
})
