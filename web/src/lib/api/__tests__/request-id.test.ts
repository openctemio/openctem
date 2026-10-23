import { afterEach, describe, expect, it, vi } from 'vitest'
import { get } from '@/lib/api/client'

function respond(status: number, body: unknown, headers: Record<string, string> = {}) {
  vi.stubGlobal(
    'fetch',
    vi.fn().mockResolvedValue(
      new Response(JSON.stringify(body), {
        status,
        headers: { 'content-type': 'application/json', ...headers },
      })
    )
  )
}

async function failure(): Promise<{ requestId?: string; statusCode: number }> {
  try {
    await get('/api/v1/findings')
  } catch (e) {
    return e as { requestId?: string; statusCode: number }
  }
  throw new Error('expected the request to fail')
}

describe('API errors carry the request id', () => {
  afterEach(() => vi.unstubAllGlobals())

  it('reads request_id from a nested error body', async () => {
    respond(500, { error: { code: 'INTERNAL', message: 'boom', request_id: 'req-123' } })
    expect((await failure()).requestId).toBe('req-123')
  })

  it('reads request_id from a flat error body', async () => {
    respond(500, { code: 'INTERNAL', message: 'boom', request_id: 'req-456' })
    expect((await failure()).requestId).toBe('req-456')
  })

  it('falls back to the X-Request-ID header', async () => {
    respond(502, { message: 'bad gateway' }, { 'x-request-id': 'req-789' })
    expect((await failure()).requestId).toBe('req-789')
  })

  it('ignores a request id that is not a short string', async () => {
    respond(500, { message: 'boom', request_id: { not: 'a string' } })
    expect((await failure()).requestId).toBeUndefined()
    respond(500, { message: 'boom', request_id: 'x'.repeat(500) })
    expect((await failure()).requestId).toBeUndefined()
  })
})
