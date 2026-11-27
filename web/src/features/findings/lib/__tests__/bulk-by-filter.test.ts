import { describe, expect, it, vi, beforeEach } from 'vitest'

const post = vi.fn()
const get = vi.fn()
vi.mock('@/lib/api/client', () => ({
  post: (...a: unknown[]) => post(...a),
  get: (...a: unknown[]) => get(...a),
}))

import { operationAsBulkResult, runFindingsBulkByFilter, selectionFilter } from '../bulk-by-filter'

beforeEach(() => {
  post.mockReset()
  get.mockReset()
})

describe('selectionFilter', () => {
  it('keeps the filter and drops what is not a selection', () => {
    const p = new URLSearchParams(
      'severity=critical,high&state=open&q=log4j&page=3&per_page=50&sort=-created_at&include=x'
    )
    expect(selectionFilter(p)).toEqual({ severity: 'critical,high', state: 'open', q: 'log4j' })
  })

  it('refuses a saved view and a list-only query (the server would refuse them)', () => {
    expect(selectionFilter(new URLSearchParams('view=abc&state=open'))).toBeNull()
    expect(selectionFilter(new URLSearchParams('fq=kev%3Dtrue'))).toBeNull()
  })
})

describe('runFindingsBulkByFilter', () => {
  it('sends the filter, the confirmed count and a fresh idempotency key', async () => {
    post.mockResolvedValue({
      operation: { id: 'op1', status: 'succeeded', total: 3, succeeded: 3, skipped: 0, failed: 0 },
    })
    const op = await runFindingsBulkByFilter('status', {
      filter: { state: 'open' },
      expectedCount: 3,
      body: { status: 'confirmed' },
    })
    expect(op.status).toBe('succeeded')
    const [url, body] = post.mock.calls[0]
    expect(url).toBe('/api/v1/findings/bulk/by-filter/status')
    expect(body).toMatchObject({
      filter: { state: 'open' },
      expected_count: 3,
      status: 'confirmed',
    })
    expect(typeof body.idempotency_key).toBe('string')
    expect(get).not.toHaveBeenCalled()
  })

  it('reads a background operation back until it ends', async () => {
    post.mockResolvedValue({
      operation: {
        id: 'op 2',
        status: 'running',
        total: 4200,
        succeeded: 0,
        skipped: 0,
        failed: 0,
      },
    })
    get
      .mockResolvedValueOnce({
        id: 'op 2',
        status: 'running',
        total: 4200,
        succeeded: 900,
        skipped: 0,
        failed: 0,
      })
      .mockResolvedValueOnce({
        id: 'op 2',
        status: 'succeeded',
        total: 4200,
        succeeded: 4190,
        skipped: 6,
        failed: 4,
      })
    const op = await runFindingsBulkByFilter(
      'assignee',
      { filter: {}, expectedCount: 4200, body: { user_id: 'u1' } },
      { sleep: async () => {} }
    )
    expect(get).toHaveBeenCalledTimes(2)
    expect(get.mock.calls[0][0]).toBe('/api/v1/operations/op%202')
    expect(op.succeeded).toBe(4190)
  })

  it('passes a changed selection through as the API error', async () => {
    post.mockRejectedValue(Object.assign(new Error('changed'), { code: 'SELECTION_CHANGED' }))
    await expect(
      runFindingsBulkByFilter('status', { filter: {}, expectedCount: 1, body: {} })
    ).rejects.toMatchObject({ code: 'SELECTION_CHANGED' })
  })
})

describe('operationAsBulkResult', () => {
  it('counts skipped and failed findings as not changed, with their reasons', () => {
    expect(
      operationAsBulkResult({
        id: 'o',
        status: 'succeeded',
        total: 5,
        succeeded: 3,
        skipped: 1,
        failed: 1,
        items: [
          { id: 'f1', outcome: 'skipped', reason: 'no longer matches the filter' },
          { id: 'f2', outcome: 'failed', reason: 'not allowed' },
        ],
      })
    ).toEqual({
      updated: 3,
      failed: 2,
      errors: ['f1: no longer matches the filter', 'f2: not allowed'],
    })
  })
})
