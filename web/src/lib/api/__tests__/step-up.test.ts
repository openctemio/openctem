import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'

import { post, del } from '@/lib/api/client'
import { ApiClientError } from '@/lib/api/error-handler'
import { isStepUpRequired, registerStepUpHandler, requestStepUp } from '@/lib/api/step-up'

function jsonResponse(status: number, body: unknown) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  })
}

const stepUpRequired = () =>
  jsonResponse(403, { code: 'STEP_UP_REQUIRED', message: 'Confirm your identity to continue' })

describe('step-up re-authentication (403 STEP_UP_REQUIRED)', () => {
  const fetchMock = vi.fn()
  let unregister: (() => void) | null = null

  beforeEach(() => {
    vi.stubGlobal('fetch', fetchMock)
  })
  afterEach(() => {
    unregister?.()
    unregister = null
    vi.unstubAllGlobals()
    fetchMock.mockReset()
  })

  it('isStepUpRequired matches only a 403 with that code', () => {
    expect(isStepUpRequired({ statusCode: 403, code: 'STEP_UP_REQUIRED' })).toBe(true)
    expect(isStepUpRequired({ statusCode: 403, code: 'STEP_UP_UNAVAILABLE' })).toBe(false)
    expect(isStepUpRequired({ statusCode: 401, code: 'STEP_UP_REQUIRED' })).toBe(false)
    expect(isStepUpRequired(undefined)).toBe(false)
  })

  it('re-authenticates through the dialog and retries the original request once', async () => {
    const handler = vi.fn(async () => true)
    unregister = registerStepUpHandler(handler)
    fetchMock
      .mockResolvedValueOnce(stepUpRequired())
      .mockResolvedValueOnce(jsonResponse(201, { id: 'k1' }))

    const res = await post<{ id: string }>('/api/v1/api-keys', { name: 'ci' })

    expect(res).toEqual({ id: 'k1' })
    expect(handler).toHaveBeenCalledTimes(1)
    expect(fetchMock).toHaveBeenCalledTimes(2)
    // The retry is the same request: same URL, method and body.
    const [first, second] = fetchMock.mock.calls
    expect(second[0]).toBe(first[0])
    expect((second[1] as RequestInit).method).toBe('POST')
    expect((second[1] as RequestInit).body).toBe((first[1] as RequestInit).body)
  })

  it('cancelling throws the original STEP_UP_REQUIRED error and does not retry', async () => {
    unregister = registerStepUpHandler(async () => false)
    fetchMock.mockImplementation(async () => stepUpRequired())

    const err = (await del('/api/v1/api-keys/k1').catch((e: unknown) => e)) as ApiClientError

    expect(err).toBeInstanceOf(ApiClientError)
    expect(err.code).toBe('STEP_UP_REQUIRED')
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })

  it('retries only once: a second STEP_UP_REQUIRED is thrown, not prompted again', async () => {
    const handler = vi.fn(async () => true)
    unregister = registerStepUpHandler(handler)
    fetchMock.mockImplementation(async () => stepUpRequired())

    const err = (await del('/api/v1/api-keys/k1').catch((e: unknown) => e)) as ApiClientError

    expect(err.code).toBe('STEP_UP_REQUIRED')
    expect(handler).toHaveBeenCalledTimes(1)
    expect(fetchMock).toHaveBeenCalledTimes(2)
  })

  it('without a mounted dialog the error is thrown as is', async () => {
    fetchMock.mockImplementation(async () => stepUpRequired())
    const err = (await del('/api/v1/api-keys/k1').catch((e: unknown) => e)) as ApiClientError
    expect(err.code).toBe('STEP_UP_REQUIRED')
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })

  it('concurrent requests share one prompt', async () => {
    let release: (ok: boolean) => void = () => undefined
    const handler = vi.fn(() => new Promise<boolean>((resolve) => (release = resolve)))
    unregister = registerStepUpHandler(handler)

    const a = requestStepUp()
    const b = requestStepUp()
    release(true)

    await expect(a).resolves.toBe(true)
    await expect(b).resolves.toBe(true)
    expect(handler).toHaveBeenCalledTimes(1)
  })

  it('a handler that throws counts as cancelled', async () => {
    unregister = registerStepUpHandler(async () => {
      throw new Error('boom')
    })
    await expect(requestStepUp()).resolves.toBe(false)
  })

  it('unregistering only removes the handler that registered', async () => {
    const first = registerStepUpHandler(async () => true)
    unregister = registerStepUpHandler(async () => true)
    first() // stale cleanup from an unmounted dialog
    await expect(requestStepUp()).resolves.toBe(true)
  })
})
