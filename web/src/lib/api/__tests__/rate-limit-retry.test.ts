import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { apiClient } from '../client'
import { ApiClientError } from '../error-handler'
import {
  MAX_READ_RETRY_WAIT_MS,
  rateLimitRetryDelayMs,
  resetRateLimitBackoff,
} from '../rate-limit-backoff'

// A read refused with 429 is retried once after the server's Retry-After, so
// a page whose panels load together does not fail for a limit that frees up a
// second later. A write is never repeated by the client.

function tooMany(retryAfter = '1') {
  return new Response(JSON.stringify({ code: 'RATE_LIMIT_EXCEEDED', message: 'slow down' }), {
    status: 429,
    headers: { 'content-type': 'application/json', 'retry-after': retryAfter },
  })
}

function ok(body: unknown) {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'content-type': 'application/json' },
  })
}

describe('apiClient on 429', () => {
  const fetchMock = vi.fn()

  beforeEach(() => {
    vi.useFakeTimers()
    vi.stubGlobal('fetch', fetchMock)
    fetchMock.mockReset()
    resetRateLimitBackoff()
  })

  afterEach(() => {
    vi.useRealTimers()
    vi.unstubAllGlobals()
  })

  it('retries a GET once after Retry-After and returns the second answer', async () => {
    fetchMock.mockResolvedValueOnce(tooMany('1')).mockResolvedValueOnce(ok({ id: 'f1' }))
    const p = apiClient<{ id: string }>('/api/v1/findings/f1')
    await vi.advanceTimersByTimeAsync(999)
    expect(fetchMock).toHaveBeenCalledTimes(1)
    await vi.advanceTimersByTimeAsync(300)
    await expect(p).resolves.toEqual({ id: 'f1' })
    expect(fetchMock).toHaveBeenCalledTimes(2)
  })

  it('gives up after one retry with the rate-limit error', async () => {
    fetchMock.mockResolvedValueOnce(tooMany()).mockResolvedValueOnce(tooMany())
    const p = apiClient('/api/v1/findings/f1')
    const caught = p.catch((e: unknown) => e)
    await vi.advanceTimersByTimeAsync(2_000)
    const err = await caught
    expect(err).toBeInstanceOf(ApiClientError)
    expect((err as ApiClientError).statusCode).toBe(429)
    expect(fetchMock).toHaveBeenCalledTimes(2)
  })

  it('never repeats a write', async () => {
    fetchMock.mockResolvedValueOnce(tooMany())
    const p = apiClient('/api/v1/findings/f1/comments', { method: 'POST', body: '{}' })
    const caught = p.catch((e: unknown) => e)
    await vi.advanceTimersByTimeAsync(2_000)
    expect(((await caught) as ApiClientError).statusCode).toBe(429)
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })

  it('does not retry a read whose caller aborted during the wait', async () => {
    fetchMock.mockResolvedValueOnce(tooMany('2'))
    const ctl = new AbortController()
    const p = apiClient('/api/v1/findings/f1', { signal: ctl.signal })
    const caught = p.catch((e: unknown) => e)
    await vi.advanceTimersByTimeAsync(500)
    ctl.abort()
    await vi.advanceTimersByTimeAsync(3_000)
    expect(((await caught) as ApiClientError).statusCode).toBe(429)
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })
})

describe('rateLimitRetryDelayMs', () => {
  it('waits the server time plus jitter, capped', () => {
    expect(rateLimitRetryDelayMs('1', 0, () => 0)).toBe(1_000)
    expect(rateLimitRetryDelayMs('1', 0, () => 0.999)).toBe(1_249)
    expect(rateLimitRetryDelayMs('120', 0, () => 0)).toBe(MAX_READ_RETRY_WAIT_MS)
    expect(rateLimitRetryDelayMs(null, 0, () => 0)).toBe(2_000)
  })
})
