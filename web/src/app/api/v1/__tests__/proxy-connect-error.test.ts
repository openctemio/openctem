/**
 * @vitest-environment node
 *
 * When the API cannot be reached, the browser gets a fixed message: the
 * connection error (which can name the internal host and port) stays in the
 * server log.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cookies } from 'next/headers'
import { NextRequest } from 'next/server'

import { GET as v1GET } from '@/app/api/v1/[...path]/route'

const APP = 'https://app.example.test'
const TENANT = '01a12aa1-8071-74f1-999a-9de298f5b787'

function jwt(expInSeconds: number): string {
  const b64 = (o: object) => Buffer.from(JSON.stringify(o)).toString('base64url')
  return `${b64({ alg: 'HS256' })}.${b64({ exp: Math.floor(Date.now() / 1000) + expInSeconds })}.sig`
}

describe('API proxy connection failure', () => {
  const fetchMock = vi.fn()

  beforeEach(() => {
    const token = jwt(600)
    vi.mocked(cookies).mockImplementation(
      async () =>
        ({
          get: (name: string) => {
            const values: Record<string, string> = {
              auth_token: token,
              refresh_token: 'rt',
              app_tenant: JSON.stringify({ id: TENANT, slug: 't', role: 'member' }),
            }
            return name in values ? { name, value: values[name] } : undefined
          },
          set: vi.fn(),
          delete: vi.fn(),
        }) as unknown as Awaited<ReturnType<typeof cookies>>
    )
    vi.stubGlobal('fetch', fetchMock)
    fetchMock.mockRejectedValue(new Error('connect ECONNREFUSED 10.0.0.5:8080'))
  })

  afterEach(() => {
    vi.unstubAllGlobals()
    fetchMock.mockReset()
  })

  it('answers 502 without the connection error text', async () => {
    const req = new NextRequest(`${APP}/api/v1/findings`, { headers: { origin: APP } })
    const res = await v1GET(req, { params: Promise.resolve({ path: ['findings'] }) })
    expect(res.status).toBe(502)
    const text = await res.text()
    expect(text).not.toContain('10.0.0.5')
    expect(text).not.toContain('ECONNREFUSED')
    expect(JSON.parse(text)).toMatchObject({ error: 'PROXY_ERROR' })
  })
})
